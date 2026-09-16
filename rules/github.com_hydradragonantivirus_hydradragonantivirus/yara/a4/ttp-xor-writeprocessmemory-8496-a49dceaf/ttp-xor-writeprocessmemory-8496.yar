rule TTP_XOR_WriteProcessMemory_8496 {
  strings:
    $key_8496 = { d3 e4 [2] e1 c6 [2] e7 f3 [2] c9 f3 [2] f6 ef }

  condition:
    any of them
}