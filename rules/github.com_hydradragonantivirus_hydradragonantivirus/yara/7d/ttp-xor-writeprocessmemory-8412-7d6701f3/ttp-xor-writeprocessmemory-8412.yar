rule TTP_XOR_WriteProcessMemory_8412 {
  strings:
    $key_8412 = { d3 60 [2] e1 42 [2] e7 77 [2] c9 77 [2] f6 6b }

  condition:
    any of them
}