rule TTP_XOR_WriteProcessMemory_8420 {
  strings:
    $key_8420 = { d3 52 [2] e1 70 [2] e7 45 [2] c9 45 [2] f6 59 }

  condition:
    any of them
}