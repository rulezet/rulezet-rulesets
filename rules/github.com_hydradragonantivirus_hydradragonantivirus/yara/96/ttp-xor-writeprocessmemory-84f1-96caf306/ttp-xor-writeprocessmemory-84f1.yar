rule TTP_XOR_WriteProcessMemory_84f1 {
  strings:
    $key_84f1 = { d3 83 [2] e1 a1 [2] e7 94 [2] c9 94 [2] f6 88 }

  condition:
    any of them
}