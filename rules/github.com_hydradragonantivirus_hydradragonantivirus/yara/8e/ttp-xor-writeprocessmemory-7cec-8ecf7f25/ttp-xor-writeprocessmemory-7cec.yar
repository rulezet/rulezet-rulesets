rule TTP_XOR_WriteProcessMemory_7cec {
  strings:
    $key_7cec = { 2b 9e [2] 19 bc [2] 1f 89 [2] 31 89 [2] 0e 95 }

  condition:
    any of them
}