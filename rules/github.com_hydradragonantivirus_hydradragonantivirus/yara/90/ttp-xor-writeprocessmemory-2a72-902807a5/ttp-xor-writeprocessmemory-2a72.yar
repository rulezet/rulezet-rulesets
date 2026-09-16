rule TTP_XOR_WriteProcessMemory_2a72 {
  strings:
    $key_2a72 = { 7d 00 [2] 4f 22 [2] 49 17 [2] 67 17 [2] 58 0b }

  condition:
    any of them
}