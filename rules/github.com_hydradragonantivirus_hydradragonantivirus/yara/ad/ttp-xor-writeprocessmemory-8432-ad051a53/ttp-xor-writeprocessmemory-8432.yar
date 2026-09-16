rule TTP_XOR_WriteProcessMemory_8432 {
  strings:
    $key_8432 = { d3 40 [2] e1 62 [2] e7 57 [2] c9 57 [2] f6 4b }

  condition:
    any of them
}