rule TTP_XOR_WriteProcessMemory_3bd2 {
  strings:
    $key_3bd2 = { 6c a0 [2] 5e 82 [2] 58 b7 [2] 76 b7 [2] 49 ab }

  condition:
    any of them
}