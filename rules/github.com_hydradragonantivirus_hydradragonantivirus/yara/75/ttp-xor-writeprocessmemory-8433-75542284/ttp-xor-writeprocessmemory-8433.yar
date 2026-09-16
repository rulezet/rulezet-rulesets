rule TTP_XOR_WriteProcessMemory_8433 {
  strings:
    $key_8433 = { d3 41 [2] e1 63 [2] e7 56 [2] c9 56 [2] f6 4a }

  condition:
    any of them
}