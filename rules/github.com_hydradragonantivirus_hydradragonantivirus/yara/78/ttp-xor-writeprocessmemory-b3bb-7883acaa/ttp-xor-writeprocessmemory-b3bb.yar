rule TTP_XOR_WriteProcessMemory_b3bb {
  strings:
    $key_b3bb = { e4 c9 [2] d6 eb [2] d0 de [2] fe de [2] c1 c2 }

  condition:
    any of them
}