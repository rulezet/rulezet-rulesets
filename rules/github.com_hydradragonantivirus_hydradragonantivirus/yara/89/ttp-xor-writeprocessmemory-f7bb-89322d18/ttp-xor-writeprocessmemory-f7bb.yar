rule TTP_XOR_WriteProcessMemory_f7bb {
  strings:
    $key_f7bb = { a0 c9 [2] 92 eb [2] 94 de [2] ba de [2] 85 c2 }

  condition:
    any of them
}