rule TTP_XOR_WriteProcessMemory_96d1 {
  strings:
    $key_96d1 = { c1 a3 [2] f3 81 [2] f5 b4 [2] db b4 [2] e4 a8 }

  condition:
    any of them
}