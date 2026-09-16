rule TTP_XOR_WriteProcessMemory_df00 {
  strings:
    $key_df00 = { 88 72 [2] ba 50 [2] bc 65 [2] 92 65 [2] ad 79 }

  condition:
    any of them
}