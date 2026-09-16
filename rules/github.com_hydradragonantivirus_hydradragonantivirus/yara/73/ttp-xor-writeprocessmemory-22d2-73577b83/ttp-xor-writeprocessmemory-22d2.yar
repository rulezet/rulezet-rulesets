rule TTP_XOR_WriteProcessMemory_22d2 {
  strings:
    $key_22d2 = { 75 a0 [2] 47 82 [2] 41 b7 [2] 6f b7 [2] 50 ab }

  condition:
    any of them
}