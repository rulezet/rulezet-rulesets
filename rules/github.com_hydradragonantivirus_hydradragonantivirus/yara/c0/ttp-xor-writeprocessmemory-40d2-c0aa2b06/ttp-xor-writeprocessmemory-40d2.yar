rule TTP_XOR_WriteProcessMemory_40d2 {
  strings:
    $key_40d2 = { 17 a0 [2] 25 82 [2] 23 b7 [2] 0d b7 [2] 32 ab }

  condition:
    any of them
}