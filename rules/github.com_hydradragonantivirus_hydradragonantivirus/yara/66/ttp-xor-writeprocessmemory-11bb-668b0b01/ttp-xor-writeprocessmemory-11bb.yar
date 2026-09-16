rule TTP_XOR_WriteProcessMemory_11bb {
  strings:
    $key_11bb = { 46 c9 [2] 74 eb [2] 72 de [2] 5c de [2] 63 c2 }

  condition:
    any of them
}