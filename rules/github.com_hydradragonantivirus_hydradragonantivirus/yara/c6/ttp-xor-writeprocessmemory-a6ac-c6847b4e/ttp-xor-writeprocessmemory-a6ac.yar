rule TTP_XOR_WriteProcessMemory_a6ac {
  strings:
    $key_a6ac = { f1 de [2] c3 fc [2] c5 c9 [2] eb c9 [2] d4 d5 }

  condition:
    any of them
}