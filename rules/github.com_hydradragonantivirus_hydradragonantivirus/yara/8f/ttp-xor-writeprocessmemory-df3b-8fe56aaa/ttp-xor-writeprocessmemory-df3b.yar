rule TTP_XOR_WriteProcessMemory_df3b {
  strings:
    $key_df3b = { 88 49 [2] ba 6b [2] bc 5e [2] 92 5e [2] ad 42 }

  condition:
    any of them
}