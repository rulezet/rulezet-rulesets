rule TTP_XOR_WriteProcessMemory_8483 {
  strings:
    $key_8483 = { d3 f1 [2] e1 d3 [2] e7 e6 [2] c9 e6 [2] f6 fa }

  condition:
    any of them
}