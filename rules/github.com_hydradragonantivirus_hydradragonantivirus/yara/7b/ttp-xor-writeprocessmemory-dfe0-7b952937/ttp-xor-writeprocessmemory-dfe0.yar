rule TTP_XOR_WriteProcessMemory_dfe0 {
  strings:
    $key_dfe0 = { 88 92 [2] ba b0 [2] bc 85 [2] 92 85 [2] ad 99 }

  condition:
    any of them
}