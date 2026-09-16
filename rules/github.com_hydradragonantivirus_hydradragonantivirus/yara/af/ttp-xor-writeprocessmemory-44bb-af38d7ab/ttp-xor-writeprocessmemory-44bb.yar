rule TTP_XOR_WriteProcessMemory_44bb {
  strings:
    $key_44bb = { 13 c9 [2] 21 eb [2] 27 de [2] 09 de [2] 36 c2 }

  condition:
    any of them
}