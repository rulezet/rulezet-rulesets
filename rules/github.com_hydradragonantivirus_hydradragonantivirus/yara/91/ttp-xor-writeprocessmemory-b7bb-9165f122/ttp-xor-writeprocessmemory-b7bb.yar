rule TTP_XOR_WriteProcessMemory_b7bb {
  strings:
    $key_b7bb = { e0 c9 [2] d2 eb [2] d4 de [2] fa de [2] c5 c2 }

  condition:
    any of them
}