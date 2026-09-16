rule TTP_XOR_WriteProcessMemory_d3bb {
  strings:
    $key_d3bb = { 84 c9 [2] b6 eb [2] b0 de [2] 9e de [2] a1 c2 }

  condition:
    any of them
}