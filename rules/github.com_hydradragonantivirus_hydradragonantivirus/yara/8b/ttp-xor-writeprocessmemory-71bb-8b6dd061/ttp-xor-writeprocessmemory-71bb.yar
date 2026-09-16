rule TTP_XOR_WriteProcessMemory_71bb {
  strings:
    $key_71bb = { 26 c9 [2] 14 eb [2] 12 de [2] 3c de [2] 03 c2 }

  condition:
    any of them
}