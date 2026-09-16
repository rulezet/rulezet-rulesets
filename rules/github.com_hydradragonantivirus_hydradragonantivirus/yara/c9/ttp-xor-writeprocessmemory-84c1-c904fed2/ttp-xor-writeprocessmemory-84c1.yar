rule TTP_XOR_WriteProcessMemory_84c1 {
  strings:
    $key_84c1 = { d3 b3 [2] e1 91 [2] e7 a4 [2] c9 a4 [2] f6 b8 }

  condition:
    any of them
}