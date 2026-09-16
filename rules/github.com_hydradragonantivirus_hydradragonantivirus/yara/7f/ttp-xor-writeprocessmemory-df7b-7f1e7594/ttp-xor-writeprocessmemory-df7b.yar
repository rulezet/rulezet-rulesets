rule TTP_XOR_WriteProcessMemory_df7b {
  strings:
    $key_df7b = { 88 09 [2] ba 2b [2] bc 1e [2] 92 1e [2] ad 02 }

  condition:
    any of them
}