rule TTP_XOR_WriteProcessMemory_d5bb {
  strings:
    $key_d5bb = { 82 c9 [2] b0 eb [2] b6 de [2] 98 de [2] a7 c2 }

  condition:
    any of them
}