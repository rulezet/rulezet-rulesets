rule TTP_XOR_WriteProcessMemory_df10 {
  strings:
    $key_df10 = { 88 62 [2] ba 40 [2] bc 75 [2] 92 75 [2] ad 69 }

  condition:
    any of them
}