rule TTP_XOR_WriteProcessMemory_c2bb {
  strings:
    $key_c2bb = { 95 c9 [2] a7 eb [2] a1 de [2] 8f de [2] b0 c2 }

  condition:
    any of them
}