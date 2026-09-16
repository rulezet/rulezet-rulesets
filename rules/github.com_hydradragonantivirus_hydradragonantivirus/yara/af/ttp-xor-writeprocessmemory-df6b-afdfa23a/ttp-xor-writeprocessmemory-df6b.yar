rule TTP_XOR_WriteProcessMemory_df6b {
  strings:
    $key_df6b = { 88 19 [2] ba 3b [2] bc 0e [2] 92 0e [2] ad 12 }

  condition:
    any of them
}