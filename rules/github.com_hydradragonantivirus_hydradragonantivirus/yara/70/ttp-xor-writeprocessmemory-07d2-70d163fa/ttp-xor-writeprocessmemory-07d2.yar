rule TTP_XOR_WriteProcessMemory_07d2 {
  strings:
    $key_07d2 = { 50 a0 [2] 62 82 [2] 64 b7 [2] 4a b7 [2] 75 ab }

  condition:
    any of them
}