rule TTP_XOR_WriteProcessMemory_82d6 {
  strings:
    $key_82d6 = { d5 a4 [2] e7 86 [2] e1 b3 [2] cf b3 [2] f0 af }

  condition:
    any of them
}