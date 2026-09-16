rule TTP_XOR_WriteProcessMemory_6cec {
  strings:
    $key_6cec = { 3b 9e [2] 09 bc [2] 0f 89 [2] 21 89 [2] 1e 95 }

  condition:
    any of them
}