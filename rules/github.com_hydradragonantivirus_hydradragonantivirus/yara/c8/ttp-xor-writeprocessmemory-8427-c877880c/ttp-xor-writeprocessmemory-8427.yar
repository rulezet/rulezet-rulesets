rule TTP_XOR_WriteProcessMemory_8427 {
  strings:
    $key_8427 = { d3 55 [2] e1 77 [2] e7 42 [2] c9 42 [2] f6 5e }

  condition:
    any of them
}