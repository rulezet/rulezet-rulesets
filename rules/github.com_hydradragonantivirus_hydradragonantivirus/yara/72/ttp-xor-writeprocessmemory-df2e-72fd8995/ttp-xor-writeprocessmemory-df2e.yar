rule TTP_XOR_WriteProcessMemory_df2e {
  strings:
    $key_df2e = { 88 5c [2] ba 7e [2] bc 4b [2] 92 4b [2] ad 57 }

  condition:
    any of them
}