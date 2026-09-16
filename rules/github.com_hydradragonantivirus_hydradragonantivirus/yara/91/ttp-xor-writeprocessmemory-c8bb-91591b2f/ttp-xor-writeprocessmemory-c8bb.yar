rule TTP_XOR_WriteProcessMemory_c8bb {
  strings:
    $key_c8bb = { 9f c9 [2] ad eb [2] ab de [2] 85 de [2] ba c2 }

  condition:
    any of them
}