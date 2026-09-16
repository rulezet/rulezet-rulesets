rule TTP_XOR_WriteProcessMemory_96d7 {
  strings:
    $key_96d7 = { c1 a5 [2] f3 87 [2] f5 b2 [2] db b2 [2] e4 ae }

  condition:
    any of them
}