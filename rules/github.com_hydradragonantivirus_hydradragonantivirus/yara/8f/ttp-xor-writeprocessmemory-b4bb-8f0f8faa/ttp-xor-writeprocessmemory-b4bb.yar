rule TTP_XOR_WriteProcessMemory_b4bb {
  strings:
    $key_b4bb = { e3 c9 [2] d1 eb [2] d7 de [2] f9 de [2] c6 c2 }

  condition:
    any of them
}