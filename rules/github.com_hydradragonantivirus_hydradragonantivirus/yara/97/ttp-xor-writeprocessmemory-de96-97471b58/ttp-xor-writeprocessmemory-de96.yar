rule TTP_XOR_WriteProcessMemory_de96 {
  strings:
    $key_de96 = { 89 e4 [2] bb c6 [2] bd f3 [2] 93 f3 [2] ac ef }

  condition:
    any of them
}