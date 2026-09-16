rule TTP_XOR_WriteProcessMemory_55d2 {
  strings:
    $key_55d2 = { 02 a0 [2] 30 82 [2] 36 b7 [2] 18 b7 [2] 27 ab }

  condition:
    any of them
}