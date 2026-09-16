rule TTP_XOR_WriteProcessMemory_36d2 {
  strings:
    $key_36d2 = { 61 a0 [2] 53 82 [2] 55 b7 [2] 7b b7 [2] 44 ab }

  condition:
    any of them
}