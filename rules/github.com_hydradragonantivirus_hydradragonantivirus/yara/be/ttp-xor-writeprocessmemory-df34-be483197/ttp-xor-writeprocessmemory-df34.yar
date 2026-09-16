rule TTP_XOR_WriteProcessMemory_df34 {
  strings:
    $key_df34 = { 88 46 [2] ba 64 [2] bc 51 [2] 92 51 [2] ad 4d }

  condition:
    any of them
}