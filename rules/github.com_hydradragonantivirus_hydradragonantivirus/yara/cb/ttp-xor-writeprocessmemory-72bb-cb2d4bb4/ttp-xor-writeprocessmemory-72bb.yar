rule TTP_XOR_WriteProcessMemory_72bb {
  strings:
    $key_72bb = { 25 c9 [2] 17 eb [2] 11 de [2] 3f de [2] 00 c2 }

  condition:
    any of them
}