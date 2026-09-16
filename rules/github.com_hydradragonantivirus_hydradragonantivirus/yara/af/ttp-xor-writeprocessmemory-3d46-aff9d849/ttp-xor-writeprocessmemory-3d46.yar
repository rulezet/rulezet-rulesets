rule TTP_XOR_WriteProcessMemory_3d46 {
  strings:
    $key_3d46 = { 6a 34 [2] 58 16 [2] 5e 23 [2] 70 23 [2] 4f 3f }

  condition:
    any of them
}