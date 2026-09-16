rule TTP_XOR_WriteProcessMemory_8407 {
  strings:
    $key_8407 = { d3 75 [2] e1 57 [2] e7 62 [2] c9 62 [2] f6 7e }

  condition:
    any of them
}