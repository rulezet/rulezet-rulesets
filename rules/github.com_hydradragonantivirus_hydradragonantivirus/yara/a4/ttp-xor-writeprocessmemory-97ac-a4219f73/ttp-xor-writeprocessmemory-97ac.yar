rule TTP_XOR_WriteProcessMemory_97ac {
  strings:
    $key_97ac = { c0 de [2] f2 fc [2] f4 c9 [2] da c9 [2] e5 d5 }

  condition:
    any of them
}