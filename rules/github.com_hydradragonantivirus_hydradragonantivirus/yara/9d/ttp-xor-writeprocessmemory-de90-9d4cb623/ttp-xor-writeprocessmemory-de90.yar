rule TTP_XOR_WriteProcessMemory_de90 {
  strings:
    $key_de90 = { 89 e2 [2] bb c0 [2] bd f5 [2] 93 f5 [2] ac e9 }

  condition:
    any of them
}