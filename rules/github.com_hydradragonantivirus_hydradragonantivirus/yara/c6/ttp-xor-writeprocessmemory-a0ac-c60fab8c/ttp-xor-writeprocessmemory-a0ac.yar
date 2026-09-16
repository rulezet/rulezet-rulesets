rule TTP_XOR_WriteProcessMemory_a0ac {
  strings:
    $key_a0ac = { f7 de [2] c5 fc [2] c3 c9 [2] ed c9 [2] d2 d5 }

  condition:
    any of them
}