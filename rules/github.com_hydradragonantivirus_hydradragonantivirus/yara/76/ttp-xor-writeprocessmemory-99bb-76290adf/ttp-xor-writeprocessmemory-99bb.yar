rule TTP_XOR_WriteProcessMemory_99bb {
  strings:
    $key_99bb = { ce c9 [2] fc eb [2] fa de [2] d4 de [2] eb c2 }

  condition:
    any of them
}