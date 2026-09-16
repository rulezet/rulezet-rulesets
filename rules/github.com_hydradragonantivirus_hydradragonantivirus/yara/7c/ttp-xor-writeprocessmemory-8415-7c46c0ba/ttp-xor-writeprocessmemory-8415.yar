rule TTP_XOR_WriteProcessMemory_8415 {
  strings:
    $key_8415 = { d3 67 [2] e1 45 [2] e7 70 [2] c9 70 [2] f6 6c }

  condition:
    any of them
}