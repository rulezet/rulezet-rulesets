rule TTP_XOR_WriteProcessMemory_02d2 {
  strings:
    $key_02d2 = { 55 a0 [2] 67 82 [2] 61 b7 [2] 4f b7 [2] 70 ab }

  condition:
    any of them
}