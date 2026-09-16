rule TTP_XOR_WriteProcessMemory_8472 {
  strings:
    $key_8472 = { d3 00 [2] e1 22 [2] e7 17 [2] c9 17 [2] f6 0b }

  condition:
    any of them
}