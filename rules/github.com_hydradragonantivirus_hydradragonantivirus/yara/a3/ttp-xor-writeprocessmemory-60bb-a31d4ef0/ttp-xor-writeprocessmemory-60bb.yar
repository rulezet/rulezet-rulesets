rule TTP_XOR_WriteProcessMemory_60bb {
  strings:
    $key_60bb = { 37 c9 [2] 05 eb [2] 03 de [2] 2d de [2] 12 c2 }

  condition:
    any of them
}