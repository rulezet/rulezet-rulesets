rule TTP_XOR_WriteProcessMemory_dfe1 {
  strings:
    $key_dfe1 = { 88 93 [2] ba b1 [2] bc 84 [2] 92 84 [2] ad 98 }

  condition:
    any of them
}