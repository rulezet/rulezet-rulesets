rule TTP_XOR_WriteProcessMemory_35bb {
  strings:
    $key_35bb = { 62 c9 [2] 50 eb [2] 56 de [2] 78 de [2] 47 c2 }

  condition:
    any of them
}