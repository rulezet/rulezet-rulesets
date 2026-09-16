rule TTP_XOR_WriteProcessMemory_c6bb {
  strings:
    $key_c6bb = { 91 c9 [2] a3 eb [2] a5 de [2] 8b de [2] b4 c2 }

  condition:
    any of them
}