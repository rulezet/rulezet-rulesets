rule TTP_XOR_WriteProcessMemory_d0bb {
  strings:
    $key_d0bb = { 87 c9 [2] b5 eb [2] b3 de [2] 9d de [2] a2 c2 }

  condition:
    any of them
}