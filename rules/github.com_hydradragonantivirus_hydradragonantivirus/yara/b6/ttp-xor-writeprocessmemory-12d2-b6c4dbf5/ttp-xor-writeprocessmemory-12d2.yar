rule TTP_XOR_WriteProcessMemory_12d2 {
  strings:
    $key_12d2 = { 45 a0 [2] 77 82 [2] 71 b7 [2] 5f b7 [2] 60 ab }

  condition:
    any of them
}