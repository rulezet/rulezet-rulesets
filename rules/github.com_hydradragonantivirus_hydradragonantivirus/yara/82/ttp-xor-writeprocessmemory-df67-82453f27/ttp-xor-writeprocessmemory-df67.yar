rule TTP_XOR_WriteProcessMemory_df67 {
  strings:
    $key_df67 = { 88 15 [2] ba 37 [2] bc 02 [2] 92 02 [2] ad 1e }

  condition:
    any of them
}