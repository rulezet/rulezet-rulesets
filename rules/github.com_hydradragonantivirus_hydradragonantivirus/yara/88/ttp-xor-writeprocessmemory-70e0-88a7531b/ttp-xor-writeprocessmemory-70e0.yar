rule TTP_XOR_WriteProcessMemory_70e0 {
  strings:
    $key_70e0 = { 27 92 [2] 15 b0 [2] 13 85 [2] 3d 85 [2] 02 99 }

  condition:
    any of them
}