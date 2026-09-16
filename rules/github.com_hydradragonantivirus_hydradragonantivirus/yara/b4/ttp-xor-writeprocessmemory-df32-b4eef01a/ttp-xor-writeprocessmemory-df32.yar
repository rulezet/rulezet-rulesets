rule TTP_XOR_WriteProcessMemory_df32 {
  strings:
    $key_df32 = { 88 40 [2] ba 62 [2] bc 57 [2] 92 57 [2] ad 4b }

  condition:
    any of them
}