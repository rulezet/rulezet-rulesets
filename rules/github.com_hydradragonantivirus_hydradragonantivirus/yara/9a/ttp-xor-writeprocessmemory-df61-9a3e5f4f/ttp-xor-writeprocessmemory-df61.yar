rule TTP_XOR_WriteProcessMemory_df61 {
  strings:
    $key_df61 = { 88 13 [2] ba 31 [2] bc 04 [2] 92 04 [2] ad 18 }

  condition:
    any of them
}