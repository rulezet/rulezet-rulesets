rule TTP_XOR_WriteProcessMemory_df1e {
  strings:
    $key_df1e = { 88 6c [2] ba 4e [2] bc 7b [2] 92 7b [2] ad 67 }

  condition:
    any of them
}