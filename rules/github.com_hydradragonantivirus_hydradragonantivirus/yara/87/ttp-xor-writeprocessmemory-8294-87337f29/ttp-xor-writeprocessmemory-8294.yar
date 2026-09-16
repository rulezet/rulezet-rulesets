rule TTP_XOR_WriteProcessMemory_8294 {
  strings:
    $key_8294 = { d5 e6 [2] e7 c4 [2] e1 f1 [2] cf f1 [2] f0 ed }

  condition:
    any of them
}