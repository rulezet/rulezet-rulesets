rule TTP_XOR_WriteProcessMemory_ce72 {
  strings:
    $key_ce72 = { 99 00 [2] ab 22 [2] ad 17 [2] 83 17 [2] bc 0b }

  condition:
    any of them
}