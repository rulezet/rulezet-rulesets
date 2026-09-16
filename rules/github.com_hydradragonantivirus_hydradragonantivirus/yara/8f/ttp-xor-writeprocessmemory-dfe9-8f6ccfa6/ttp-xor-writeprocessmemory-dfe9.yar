rule TTP_XOR_WriteProcessMemory_dfe9 {
  strings:
    $key_dfe9 = { 88 9b [2] ba b9 [2] bc 8c [2] 92 8c [2] ad 90 }

  condition:
    any of them
}