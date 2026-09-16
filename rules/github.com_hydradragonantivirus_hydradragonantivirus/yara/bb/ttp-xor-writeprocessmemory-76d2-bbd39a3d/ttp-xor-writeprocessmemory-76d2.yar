rule TTP_XOR_WriteProcessMemory_76d2 {
  strings:
    $key_76d2 = { 21 a0 [2] 13 82 [2] 15 b7 [2] 3b b7 [2] 04 ab }

  condition:
    any of them
}