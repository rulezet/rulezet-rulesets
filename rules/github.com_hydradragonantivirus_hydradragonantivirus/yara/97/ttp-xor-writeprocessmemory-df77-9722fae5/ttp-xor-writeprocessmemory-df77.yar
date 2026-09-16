rule TTP_XOR_WriteProcessMemory_df77 {
  strings:
    $key_df77 = { 88 05 [2] ba 27 [2] bc 12 [2] 92 12 [2] ad 0e }

  condition:
    any of them
}