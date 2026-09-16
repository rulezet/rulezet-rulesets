rule TTP_XOR_WriteProcessMemory_8426 {
  strings:
    $key_8426 = { d3 54 [2] e1 76 [2] e7 43 [2] c9 43 [2] f6 5f }

  condition:
    any of them
}