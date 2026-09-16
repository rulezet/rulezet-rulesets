rule TTP_XOR_WriteProcessMemory_4cec {
  strings:
    $key_4cec = { 1b 9e [2] 29 bc [2] 2f 89 [2] 01 89 [2] 3e 95 }

  condition:
    any of them
}