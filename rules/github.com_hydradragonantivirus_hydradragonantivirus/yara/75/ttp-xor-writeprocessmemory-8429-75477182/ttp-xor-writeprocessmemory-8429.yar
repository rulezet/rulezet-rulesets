rule TTP_XOR_WriteProcessMemory_8429 {
  strings:
    $key_8429 = { d3 5b [2] e1 79 [2] e7 4c [2] c9 4c [2] f6 50 }

  condition:
    any of them
}