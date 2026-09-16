rule TTP_XOR_WriteProcessMemory_dff3 {
  strings:
    $key_dff3 = { 88 81 [2] ba a3 [2] bc 96 [2] 92 96 [2] ad 8a }

  condition:
    any of them
}