rule TTP_XOR_WriteProcessMemory_8454 {
  strings:
    $key_8454 = { d3 26 [2] e1 04 [2] e7 31 [2] c9 31 [2] f6 2d }

  condition:
    any of them
}