rule TTP_XOR_WriteProcessMemory_8467 {
  strings:
    $key_8467 = { d3 15 [2] e1 37 [2] e7 02 [2] c9 02 [2] f6 1e }

  condition:
    any of them
}