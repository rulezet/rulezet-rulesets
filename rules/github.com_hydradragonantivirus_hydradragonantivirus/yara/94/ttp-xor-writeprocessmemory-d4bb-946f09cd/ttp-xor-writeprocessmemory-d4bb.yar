rule TTP_XOR_WriteProcessMemory_d4bb {
  strings:
    $key_d4bb = { 83 c9 [2] b1 eb [2] b7 de [2] 99 de [2] a6 c2 }

  condition:
    any of them
}