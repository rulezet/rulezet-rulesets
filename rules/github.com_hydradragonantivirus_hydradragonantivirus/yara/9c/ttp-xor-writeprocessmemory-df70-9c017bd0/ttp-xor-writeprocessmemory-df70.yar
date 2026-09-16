rule TTP_XOR_WriteProcessMemory_df70 {
  strings:
    $key_df70 = { 88 02 [2] ba 20 [2] bc 15 [2] 92 15 [2] ad 09 }

  condition:
    any of them
}