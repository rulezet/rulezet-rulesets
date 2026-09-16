rule TTP_XOR_WriteProcessMemory_8475 {
  strings:
    $key_8475 = { d3 07 [2] e1 25 [2] e7 10 [2] c9 10 [2] f6 0c }

  condition:
    any of them
}