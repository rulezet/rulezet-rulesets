rule TTP_XOR_WriteProcessMemory_8494 {
  strings:
    $key_8494 = { d3 e6 [2] e1 c4 [2] e7 f1 [2] c9 f1 [2] f6 ed }

  condition:
    any of them
}