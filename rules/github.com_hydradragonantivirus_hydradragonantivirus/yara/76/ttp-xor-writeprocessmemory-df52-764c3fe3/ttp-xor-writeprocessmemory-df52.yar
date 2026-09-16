rule TTP_XOR_WriteProcessMemory_df52 {
  strings:
    $key_df52 = { 88 20 [2] ba 02 [2] bc 37 [2] 92 37 [2] ad 2b }

  condition:
    any of them
}