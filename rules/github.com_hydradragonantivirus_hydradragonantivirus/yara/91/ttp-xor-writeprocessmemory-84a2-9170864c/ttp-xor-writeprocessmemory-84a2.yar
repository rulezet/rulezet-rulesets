rule TTP_XOR_WriteProcessMemory_84a2 {
  strings:
    $key_84a2 = { d3 d0 [2] e1 f2 [2] e7 c7 [2] c9 c7 [2] f6 db }

  condition:
    any of them
}