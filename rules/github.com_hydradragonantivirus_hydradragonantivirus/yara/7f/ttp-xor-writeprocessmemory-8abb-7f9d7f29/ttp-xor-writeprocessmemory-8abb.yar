rule TTP_XOR_WriteProcessMemory_8abb {
  strings:
    $key_8abb = { dd c9 [2] ef eb [2] e9 de [2] c7 de [2] f8 c2 }

  condition:
    any of them
}