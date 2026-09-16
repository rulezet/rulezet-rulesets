rule TTP_XOR_WriteProcessMemory_dfe3 {
  strings:
    $key_dfe3 = { 88 91 [2] ba b3 [2] bc 86 [2] 92 86 [2] ad 9a }

  condition:
    any of them
}