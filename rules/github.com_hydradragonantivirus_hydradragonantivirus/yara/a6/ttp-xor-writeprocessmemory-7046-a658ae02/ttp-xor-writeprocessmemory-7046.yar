rule TTP_XOR_WriteProcessMemory_7046 {
  strings:
    $key_7046 = { 27 34 [2] 15 16 [2] 13 23 [2] 3d 23 [2] 02 3f }

  condition:
    any of them
}