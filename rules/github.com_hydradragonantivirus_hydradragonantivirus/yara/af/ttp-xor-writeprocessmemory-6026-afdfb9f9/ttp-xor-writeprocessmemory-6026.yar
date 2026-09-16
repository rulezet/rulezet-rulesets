rule TTP_XOR_WriteProcessMemory_6026 {
  strings:
    $key_6026 = { 37 54 [2] 05 76 [2] 03 43 [2] 2d 43 [2] 12 5f }

  condition:
    any of them
}