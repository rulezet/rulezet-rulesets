rule TTP_XOR_WriteProcessMemory_26d2 {
  strings:
    $key_26d2 = { 71 a0 [2] 43 82 [2] 45 b7 [2] 6b b7 [2] 54 ab }

  condition:
    any of them
}