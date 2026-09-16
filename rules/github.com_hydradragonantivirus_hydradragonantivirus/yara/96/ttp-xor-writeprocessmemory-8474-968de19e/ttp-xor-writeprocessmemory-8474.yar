rule TTP_XOR_WriteProcessMemory_8474 {
  strings:
    $key_8474 = { d3 06 [2] e1 24 [2] e7 11 [2] c9 11 [2] f6 0d }

  condition:
    any of them
}