rule TTP_XOR_WriteProcessMemory_96d2 {
  strings:
    $key_96d2 = { c1 a0 [2] f3 82 [2] f5 b7 [2] db b7 [2] e4 ab }

  condition:
    any of them
}