rule TTP_XOR_WriteProcessMemory_8455 {
  strings:
    $key_8455 = { d3 27 [2] e1 05 [2] e7 30 [2] c9 30 [2] f6 2c }

  condition:
    any of them
}