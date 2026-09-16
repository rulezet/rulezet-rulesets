rule TTP_XOR_WriteProcessMemory_82c1 {
  strings:
    $key_82c1 = { d5 b3 [2] e7 91 [2] e1 a4 [2] cf a4 [2] f0 b8 }

  condition:
    any of them
}