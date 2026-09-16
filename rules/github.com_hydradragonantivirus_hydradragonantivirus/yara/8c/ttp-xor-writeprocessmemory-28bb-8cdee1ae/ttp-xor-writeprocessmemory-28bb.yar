rule TTP_XOR_WriteProcessMemory_28bb {
  strings:
    $key_28bb = { 7f c9 [2] 4d eb [2] 4b de [2] 65 de [2] 5a c2 }

  condition:
    any of them
}