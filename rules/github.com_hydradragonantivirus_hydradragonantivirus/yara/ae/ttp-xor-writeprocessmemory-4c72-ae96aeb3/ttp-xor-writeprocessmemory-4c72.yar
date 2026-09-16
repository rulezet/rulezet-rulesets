rule TTP_XOR_WriteProcessMemory_4c72 {
  strings:
    $key_4c72 = { 1b 00 [2] 29 22 [2] 2f 17 [2] 01 17 [2] 3e 0b }

  condition:
    any of them
}