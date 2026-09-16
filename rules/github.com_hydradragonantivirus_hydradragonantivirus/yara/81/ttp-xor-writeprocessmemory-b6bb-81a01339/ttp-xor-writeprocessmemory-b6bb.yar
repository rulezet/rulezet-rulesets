rule TTP_XOR_WriteProcessMemory_b6bb {
  strings:
    $key_b6bb = { e1 c9 [2] d3 eb [2] d5 de [2] fb de [2] c4 c2 }

  condition:
    any of them
}