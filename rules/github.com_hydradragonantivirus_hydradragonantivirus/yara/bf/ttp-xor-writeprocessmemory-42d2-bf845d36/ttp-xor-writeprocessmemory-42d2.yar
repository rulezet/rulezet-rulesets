rule TTP_XOR_WriteProcessMemory_42d2 {
  strings:
    $key_42d2 = { 15 a0 [2] 27 82 [2] 21 b7 [2] 0f b7 [2] 30 ab }

  condition:
    any of them
}