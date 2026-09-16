rule TTP_XOR_WriteProcessMemory_d972 {
  strings:
    $key_d972 = { 8e 00 [2] bc 22 [2] ba 17 [2] 94 17 [2] ab 0b }

  condition:
    any of them
}