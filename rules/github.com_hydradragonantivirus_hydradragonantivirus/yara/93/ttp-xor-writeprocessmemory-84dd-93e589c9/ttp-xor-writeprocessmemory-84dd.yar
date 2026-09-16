rule TTP_XOR_WriteProcessMemory_84dd {
  strings:
    $key_84dd = { d3 af [2] e1 8d [2] e7 b8 [2] c9 b8 [2] f6 a4 }

  condition:
    any of them
}