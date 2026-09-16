rule TTP_XOR_WriteProcessMemory_5072 {
  strings:
    $key_5072 = { 07 00 [2] 35 22 [2] 33 17 [2] 1d 17 [2] 22 0b }

  condition:
    any of them
}