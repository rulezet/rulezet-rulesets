rule TTP_XOR_WriteProcessMemory_de80 {
  strings:
    $key_de80 = { 89 f2 [2] bb d0 [2] bd e5 [2] 93 e5 [2] ac f9 }

  condition:
    any of them
}