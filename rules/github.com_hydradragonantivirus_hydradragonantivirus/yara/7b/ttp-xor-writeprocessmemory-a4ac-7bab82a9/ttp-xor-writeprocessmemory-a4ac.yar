rule TTP_XOR_WriteProcessMemory_a4ac {
  strings:
    $key_a4ac = { f3 de [2] c1 fc [2] c7 c9 [2] e9 c9 [2] d6 d5 }

  condition:
    any of them
}