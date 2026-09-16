rule TTP_XOR_WriteProcessMemory_8484 {
  strings:
    $key_8484 = { d3 f6 [2] e1 d4 [2] e7 e1 [2] c9 e1 [2] f6 fd }

  condition:
    any of them
}