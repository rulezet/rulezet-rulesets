rule TTP_XOR_WriteProcessMemory_df50 {
  strings:
    $key_df50 = { 88 22 [2] ba 00 [2] bc 35 [2] 92 35 [2] ad 29 }

  condition:
    any of them
}