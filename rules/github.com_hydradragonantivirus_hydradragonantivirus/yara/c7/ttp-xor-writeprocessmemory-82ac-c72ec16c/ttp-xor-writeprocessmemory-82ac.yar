rule TTP_XOR_WriteProcessMemory_82ac {
  strings:
    $key_82ac = { d5 de [2] e7 fc [2] e1 c9 [2] cf c9 [2] f0 d5 }

  condition:
    any of them
}