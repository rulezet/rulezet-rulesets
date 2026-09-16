rule TTP_XOR_WriteProcessMemory_4a72 {
  strings:
    $key_4a72 = { 1d 00 [2] 2f 22 [2] 29 17 [2] 07 17 [2] 38 0b }

  condition:
    any of them
}