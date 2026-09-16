rule TTP_XOR_WriteProcessMemory_7016 {
  strings:
    $key_7016 = { 27 64 [2] 15 46 [2] 13 73 [2] 3d 73 [2] 02 6f }

  condition:
    any of them
}