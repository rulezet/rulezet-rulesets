rule TTP_XOR_WriteProcessMemory_df19 {
  strings:
    $key_df19 = { 88 6b [2] ba 49 [2] bc 7c [2] 92 7c [2] ad 60 }

  condition:
    any of them
}