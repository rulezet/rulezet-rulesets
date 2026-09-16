rule TTP_XOR_WriteProcessMemory_95ac {
  strings:
    $key_95ac = { c2 de [2] f0 fc [2] f6 c9 [2] d8 c9 [2] e7 d5 }

  condition:
    any of them
}