rule TTP_XOR_WriteProcessMemory_8405 {
  strings:
    $key_8405 = { d3 77 [2] e1 55 [2] e7 60 [2] c9 60 [2] f6 7c }

  condition:
    any of them
}