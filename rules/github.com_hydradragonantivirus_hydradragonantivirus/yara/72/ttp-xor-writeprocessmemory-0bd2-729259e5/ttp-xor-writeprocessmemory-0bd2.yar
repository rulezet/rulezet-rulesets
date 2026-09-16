rule TTP_XOR_WriteProcessMemory_0bd2 {
  strings:
    $key_0bd2 = { 5c a0 [2] 6e 82 [2] 68 b7 [2] 46 b7 [2] 79 ab }

  condition:
    any of them
}