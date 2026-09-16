rule TTP_XOR_WriteProcessMemory_70d4 {
  strings:
    $key_70d4 = { 27 a6 [2] 15 84 [2] 13 b1 [2] 3d b1 [2] 02 ad }

  condition:
    any of them
}