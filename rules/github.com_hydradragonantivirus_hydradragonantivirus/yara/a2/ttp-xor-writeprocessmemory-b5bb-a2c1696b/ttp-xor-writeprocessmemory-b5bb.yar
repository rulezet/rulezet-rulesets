rule TTP_XOR_WriteProcessMemory_b5bb {
  strings:
    $key_b5bb = { e2 c9 [2] d0 eb [2] d6 de [2] f8 de [2] c7 c2 }

  condition:
    any of them
}