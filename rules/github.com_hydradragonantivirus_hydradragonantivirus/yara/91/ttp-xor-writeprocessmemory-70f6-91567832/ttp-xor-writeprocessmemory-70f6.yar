rule TTP_XOR_WriteProcessMemory_70f6 {
  strings:
    $key_70f6 = { 27 84 [2] 15 a6 [2] 13 93 [2] 3d 93 [2] 02 8f }

  condition:
    any of them
}