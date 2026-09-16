rule TTP_XOR_WriteProcessMemory_8421 {
  strings:
    $key_8421 = { d3 53 [2] e1 71 [2] e7 44 [2] c9 44 [2] f6 58 }

  condition:
    any of them
}