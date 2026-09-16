rule TTP_XOR_WriteProcessMemory_b1bb {
  strings:
    $key_b1bb = { e6 c9 [2] d4 eb [2] d2 de [2] fc de [2] c3 c2 }

  condition:
    any of them
}