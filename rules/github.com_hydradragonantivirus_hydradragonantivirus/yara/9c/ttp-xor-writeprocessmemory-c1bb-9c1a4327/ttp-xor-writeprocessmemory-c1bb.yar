rule TTP_XOR_WriteProcessMemory_c1bb {
  strings:
    $key_c1bb = { 96 c9 [2] a4 eb [2] a2 de [2] 8c de [2] b3 c2 }

  condition:
    any of them
}