rule TTP_XOR_WriteProcessMemory_65bb {
  strings:
    $key_65bb = { 32 c9 [2] 00 eb [2] 06 de [2] 28 de [2] 17 c2 }

  condition:
    any of them
}