rule TTP_XOR_WriteProcessMemory_22bb {
  strings:
    $key_22bb = { 75 c9 [2] 47 eb [2] 41 de [2] 6f de [2] 50 c2 }

  condition:
    any of them
}