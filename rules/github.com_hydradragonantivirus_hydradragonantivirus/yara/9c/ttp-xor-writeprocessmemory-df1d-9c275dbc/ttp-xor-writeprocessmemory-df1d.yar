rule TTP_XOR_WriteProcessMemory_df1d {
  strings:
    $key_df1d = { 88 6f [2] ba 4d [2] bc 78 [2] 92 78 [2] ad 64 }

  condition:
    any of them
}