rule TTP_XOR_WriteProcessMemory_35d1 {
  strings:
    $key_35d1 = { 62 a3 [2] 50 81 [2] 56 b4 [2] 78 b4 [2] 47 a8 }

  condition:
    any of them
}