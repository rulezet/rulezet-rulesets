rule TTP_XOR_WriteProcessMemory_76d1 {
  strings:
    $key_76d1 = { 21 a3 [2] 13 81 [2] 15 b4 [2] 3b b4 [2] 04 a8 }

  condition:
    any of them
}