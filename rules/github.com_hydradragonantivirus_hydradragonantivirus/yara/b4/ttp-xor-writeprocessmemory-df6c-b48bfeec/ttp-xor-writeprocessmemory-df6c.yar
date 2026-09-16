rule TTP_XOR_WriteProcessMemory_df6c {
  strings:
    $key_df6c = { 88 1e [2] ba 3c [2] bc 09 [2] 92 09 [2] ad 15 }

  condition:
    any of them
}