rule TTP_XOR_WriteProcessMemory_6072 {
  strings:
    $key_6072 = { 37 00 [2] 05 22 [2] 03 17 [2] 2d 17 [2] 12 0b }

  condition:
    any of them
}