rule TTP_XOR_WriteProcessMemory_1f72 {
  strings:
    $key_1f72 = { 48 00 [2] 7a 22 [2] 7c 17 [2] 52 17 [2] 6d 0b }

  condition:
    any of them
}