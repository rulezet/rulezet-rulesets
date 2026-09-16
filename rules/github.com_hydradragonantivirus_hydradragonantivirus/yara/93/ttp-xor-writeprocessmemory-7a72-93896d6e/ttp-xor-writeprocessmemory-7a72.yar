rule TTP_XOR_WriteProcessMemory_7a72 {
  strings:
    $key_7a72 = { 2d 00 [2] 1f 22 [2] 19 17 [2] 37 17 [2] 08 0b }

  condition:
    any of them
}