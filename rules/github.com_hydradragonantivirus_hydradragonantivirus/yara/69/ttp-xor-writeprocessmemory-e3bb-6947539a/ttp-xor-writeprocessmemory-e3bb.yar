rule TTP_XOR_WriteProcessMemory_e3bb {
  strings:
    $key_e3bb = { b4 c9 [2] 86 eb [2] 80 de [2] ae de [2] 91 c2 }

  condition:
    any of them
}