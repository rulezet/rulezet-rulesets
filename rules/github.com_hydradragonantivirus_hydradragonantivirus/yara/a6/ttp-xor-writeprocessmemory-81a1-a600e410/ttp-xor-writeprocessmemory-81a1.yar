rule TTP_XOR_WriteProcessMemory_81a1 {
  strings:
    $key_81a1 = { d6 d3 [2] e4 f1 [2] e2 c4 [2] cc c4 [2] f3 d8 }

  condition:
    any of them
}