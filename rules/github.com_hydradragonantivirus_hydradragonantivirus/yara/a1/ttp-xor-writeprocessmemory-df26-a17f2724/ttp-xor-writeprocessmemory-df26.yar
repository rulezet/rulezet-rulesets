rule TTP_XOR_WriteProcessMemory_df26 {
  strings:
    $key_df26 = { 88 54 [2] ba 76 [2] bc 43 [2] 92 43 [2] ad 5f }

  condition:
    any of them
}