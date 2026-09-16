rule TTP_XOR_WriteProcessMemory_85bb {
  strings:
    $key_85bb = { d2 c9 [2] e0 eb [2] e6 de [2] c8 de [2] f7 c2 }

  condition:
    any of them
}