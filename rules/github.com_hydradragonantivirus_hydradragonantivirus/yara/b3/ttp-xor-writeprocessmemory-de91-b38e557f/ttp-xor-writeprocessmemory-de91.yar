rule TTP_XOR_WriteProcessMemory_de91 {
  strings:
    $key_de91 = { 89 e3 [2] bb c1 [2] bd f4 [2] 93 f4 [2] ac e8 }

  condition:
    any of them
}