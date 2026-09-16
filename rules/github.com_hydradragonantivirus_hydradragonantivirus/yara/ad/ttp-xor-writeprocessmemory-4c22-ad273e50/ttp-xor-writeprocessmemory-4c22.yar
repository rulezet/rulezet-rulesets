rule TTP_XOR_WriteProcessMemory_4c22 {
  strings:
    $key_4c22 = { 1b 50 [2] 29 72 [2] 2f 47 [2] 01 47 [2] 3e 5b }

  condition:
    any of them
}