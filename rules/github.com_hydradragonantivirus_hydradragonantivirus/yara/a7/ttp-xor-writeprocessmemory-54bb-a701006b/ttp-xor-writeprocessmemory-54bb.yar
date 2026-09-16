rule TTP_XOR_WriteProcessMemory_54bb {
  strings:
    $key_54bb = { 03 c9 [2] 31 eb [2] 37 de [2] 19 de [2] 26 c2 }

  condition:
    any of them
}