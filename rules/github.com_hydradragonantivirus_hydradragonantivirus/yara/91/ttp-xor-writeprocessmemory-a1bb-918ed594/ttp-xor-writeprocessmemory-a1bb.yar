rule TTP_XOR_WriteProcessMemory_a1bb {
  strings:
    $key_a1bb = { f6 c9 [2] c4 eb [2] c2 de [2] ec de [2] d3 c2 }

  condition:
    any of them
}