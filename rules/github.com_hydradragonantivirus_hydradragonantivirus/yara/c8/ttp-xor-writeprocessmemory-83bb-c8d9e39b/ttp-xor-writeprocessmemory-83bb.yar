rule TTP_XOR_WriteProcessMemory_83bb {
  strings:
    $key_83bb = { d4 c9 [2] e6 eb [2] e0 de [2] ce de [2] f1 c2 }

  condition:
    any of them
}