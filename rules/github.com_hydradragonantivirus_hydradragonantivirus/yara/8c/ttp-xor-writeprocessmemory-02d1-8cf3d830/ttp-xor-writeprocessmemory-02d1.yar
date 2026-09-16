rule TTP_XOR_WriteProcessMemory_02d1 {
  strings:
    $key_02d1 = { 55 a3 [2] 67 81 [2] 61 b4 [2] 4f b4 [2] 70 a8 }

  condition:
    any of them
}