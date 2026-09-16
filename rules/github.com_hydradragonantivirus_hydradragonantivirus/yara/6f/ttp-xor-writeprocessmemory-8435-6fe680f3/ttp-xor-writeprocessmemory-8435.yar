rule TTP_XOR_WriteProcessMemory_8435 {
  strings:
    $key_8435 = { d3 47 [2] e1 65 [2] e7 50 [2] c9 50 [2] f6 4c }

  condition:
    any of them
}