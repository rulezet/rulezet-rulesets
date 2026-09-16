rule TTP_XOR_WriteProcessMemory_de98 {
  strings:
    $key_de98 = { 89 ea [2] bb c8 [2] bd fd [2] 93 fd [2] ac e1 }

  condition:
    any of them
}