rule TTP_XOR_WriteProcessMemory_12bb {
  strings:
    $key_12bb = { 45 c9 [2] 77 eb [2] 71 de [2] 5f de [2] 60 c2 }

  condition:
    any of them
}