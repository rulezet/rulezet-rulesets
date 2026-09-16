rule TTP_XOR_WriteProcessMemory_8452 {
  strings:
    $key_8452 = { d3 20 [2] e1 02 [2] e7 37 [2] c9 37 [2] f6 2b }

  condition:
    any of them
}