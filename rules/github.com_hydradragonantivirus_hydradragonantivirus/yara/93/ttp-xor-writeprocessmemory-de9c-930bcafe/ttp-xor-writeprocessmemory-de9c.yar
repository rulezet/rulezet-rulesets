rule TTP_XOR_WriteProcessMemory_de9c {
  strings:
    $key_de9c = { 89 ee [2] bb cc [2] bd f9 [2] 93 f9 [2] ac e5 }

  condition:
    any of them
}