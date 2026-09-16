rule TTP_XOR_WriteProcessMemory_10bb {
  strings:
    $key_10bb = { 47 c9 [2] 75 eb [2] 73 de [2] 5d de [2] 62 c2 }

  condition:
    any of them
}