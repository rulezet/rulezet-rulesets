rule TTP_XOR_WriteProcessMemory_53bb {
  strings:
    $key_53bb = { 04 c9 [2] 36 eb [2] 30 de [2] 1e de [2] 21 c2 }

  condition:
    any of them
}