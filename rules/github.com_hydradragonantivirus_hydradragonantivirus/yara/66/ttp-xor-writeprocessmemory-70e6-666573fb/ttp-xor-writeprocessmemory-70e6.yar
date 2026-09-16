rule TTP_XOR_WriteProcessMemory_70e6 {
  strings:
    $key_70e6 = { 27 94 [2] 15 b6 [2] 13 83 [2] 3d 83 [2] 02 9f }

  condition:
    any of them
}