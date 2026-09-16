rule TTP_XOR_WriteProcessMemory_df42 {
  strings:
    $key_df42 = { 88 30 [2] ba 12 [2] bc 27 [2] 92 27 [2] ad 3b }

  condition:
    any of them
}