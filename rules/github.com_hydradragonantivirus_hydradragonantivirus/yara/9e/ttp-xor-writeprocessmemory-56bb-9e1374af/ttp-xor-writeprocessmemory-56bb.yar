rule TTP_XOR_WriteProcessMemory_56bb {
  strings:
    $key_56bb = { 01 c9 [2] 33 eb [2] 35 de [2] 1b de [2] 24 c2 }

  condition:
    any of them
}