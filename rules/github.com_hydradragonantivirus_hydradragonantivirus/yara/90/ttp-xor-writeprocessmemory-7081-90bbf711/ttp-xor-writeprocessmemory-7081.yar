rule TTP_XOR_WriteProcessMemory_7081 {
  strings:
    $key_7081 = { 27 f3 [2] 15 d1 [2] 13 e4 [2] 3d e4 [2] 02 f8 }

  condition:
    any of them
}