rule TTP_XOR_WriteProcessMemory_8465 {
  strings:
    $key_8465 = { d3 17 [2] e1 35 [2] e7 00 [2] c9 00 [2] f6 1c }

  condition:
    any of them
}