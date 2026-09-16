rule TTP_XOR_WriteProcessMemory_dfe8 {
  strings:
    $key_dfe8 = { 88 9a [2] ba b8 [2] bc 8d [2] 92 8d [2] ad 91 }

  condition:
    any of them
}