rule TTP_XOR_WriteProcessMemory_50d1 {
  strings:
    $key_50d1 = { 07 a3 [2] 35 81 [2] 33 b4 [2] 1d b4 [2] 22 a8 }

  condition:
    any of them
}