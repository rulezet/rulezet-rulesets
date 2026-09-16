rule TTP_XOR_WriteProcessMemory_a5bb {
  strings:
    $key_a5bb = { f2 c9 [2] c0 eb [2] c6 de [2] e8 de [2] d7 c2 }

  condition:
    any of them
}