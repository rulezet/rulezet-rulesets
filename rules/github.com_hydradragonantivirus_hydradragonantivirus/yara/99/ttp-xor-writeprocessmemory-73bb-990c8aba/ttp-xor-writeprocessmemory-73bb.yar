rule TTP_XOR_WriteProcessMemory_73bb {
  strings:
    $key_73bb = { 24 c9 [2] 16 eb [2] 10 de [2] 3e de [2] 01 c2 }

  condition:
    any of them
}