rule TTP_XOR_WriteProcessMemory_60f3 {
  strings:
    $key_60f3 = { 37 81 [2] 05 a3 [2] 03 96 [2] 2d 96 [2] 12 8a }

  condition:
    any of them
}