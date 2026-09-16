rule TTP_XOR_WriteProcessMemory_a7bb {
  strings:
    $key_a7bb = { f0 c9 [2] c2 eb [2] c4 de [2] ea de [2] d5 c2 }

  condition:
    any of them
}