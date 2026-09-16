rule TTP_XOR_WriteProcessMemory_de84 {
  strings:
    $key_de84 = { 89 f6 [2] bb d4 [2] bd e1 [2] 93 e1 [2] ac fd }

  condition:
    any of them
}