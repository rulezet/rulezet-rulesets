rule TTP_XOR_WriteProcessMemory_60d2 {
  strings:
    $key_60d2 = { 37 a0 [2] 05 82 [2] 03 b7 [2] 2d b7 [2] 12 ab }

  condition:
    any of them
}