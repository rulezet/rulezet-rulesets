rule TTP_XOR_WriteProcessMemory_8498 {
  strings:
    $key_8498 = { d3 ea [2] e1 c8 [2] e7 fd [2] c9 fd [2] f6 e1 }

  condition:
    any of them
}