rule TTP_XOR_WriteProcessMemory_81ac {
  strings:
    $key_81ac = { d6 de [2] e4 fc [2] e2 c9 [2] cc c9 [2] f3 d5 }

  condition:
    any of them
}