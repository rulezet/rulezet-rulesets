rule TTP_XOR_WriteProcessMemory_8529 {
  strings:
    $key_8529 = { d2 5b [2] e0 79 [2] e6 4c [2] c8 4c [2] f7 50 }

  condition:
    any of them
}