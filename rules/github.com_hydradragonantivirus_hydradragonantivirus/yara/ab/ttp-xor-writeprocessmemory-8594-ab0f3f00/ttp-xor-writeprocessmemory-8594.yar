rule TTP_XOR_WriteProcessMemory_8594 {
  strings:
    $key_8594 = { d2 e6 [2] e0 c4 [2] e6 f1 [2] c8 f1 [2] f7 ed }

  condition:
    any of them
}