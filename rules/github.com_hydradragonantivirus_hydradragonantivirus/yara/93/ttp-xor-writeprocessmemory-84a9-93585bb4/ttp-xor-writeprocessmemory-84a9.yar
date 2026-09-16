rule TTP_XOR_WriteProcessMemory_84a9 {
  strings:
    $key_84a9 = { d3 db [2] e1 f9 [2] e7 cc [2] c9 cc [2] f6 d0 }

  condition:
    any of them
}