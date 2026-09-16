rule TTP_XOR_WriteProcessMemory_df2d {
  strings:
    $key_df2d = { 88 5f [2] ba 7d [2] bc 48 [2] 92 48 [2] ad 54 }

  condition:
    any of them
}