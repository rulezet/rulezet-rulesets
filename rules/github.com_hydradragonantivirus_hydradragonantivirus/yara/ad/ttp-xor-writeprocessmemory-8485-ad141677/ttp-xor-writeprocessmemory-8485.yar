rule TTP_XOR_WriteProcessMemory_8485 {
  strings:
    $key_8485 = { d3 f7 [2] e1 d5 [2] e7 e0 [2] c9 e0 [2] f6 fc }

  condition:
    any of them
}