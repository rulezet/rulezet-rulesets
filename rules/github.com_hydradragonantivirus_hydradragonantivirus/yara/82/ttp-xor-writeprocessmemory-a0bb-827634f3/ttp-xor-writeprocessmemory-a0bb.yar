rule TTP_XOR_WriteProcessMemory_a0bb {
  strings:
    $key_a0bb = { f7 c9 [2] c5 eb [2] c3 de [2] ed de [2] d2 c2 }

  condition:
    any of them
}