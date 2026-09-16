rule TTP_XOR_WriteProcessMemory_6046 {
  strings:
    $key_6046 = { 37 34 [2] 05 16 [2] 03 23 [2] 2d 23 [2] 12 3f }

  condition:
    any of them
}