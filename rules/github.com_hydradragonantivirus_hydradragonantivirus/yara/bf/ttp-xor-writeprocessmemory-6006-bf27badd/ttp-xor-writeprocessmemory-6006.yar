rule TTP_XOR_WriteProcessMemory_6006 {
  strings:
    $key_6006 = { 37 74 [2] 05 56 [2] 03 63 [2] 2d 63 [2] 12 7f }

  condition:
    any of them
}