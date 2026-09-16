rule TTP_XOR_WriteProcessMemory_96d6 {
  strings:
    $key_96d6 = { c1 a4 [2] f3 86 [2] f5 b3 [2] db b3 [2] e4 af }

  condition:
    any of them
}