rule TTP_XOR_WriteProcessMemory_df1b {
  strings:
    $key_df1b = { 88 69 [2] ba 4b [2] bc 7e [2] 92 7e [2] ad 62 }

  condition:
    any of them
}