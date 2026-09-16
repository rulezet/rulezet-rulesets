rule TTP_XOR_WriteProcessMemory_6ae6 {
  strings:
    $key_6ae6 = { 3d 94 [2] 0f b6 [2] 09 83 [2] 27 83 [2] 18 9f }

  condition:
    any of them
}