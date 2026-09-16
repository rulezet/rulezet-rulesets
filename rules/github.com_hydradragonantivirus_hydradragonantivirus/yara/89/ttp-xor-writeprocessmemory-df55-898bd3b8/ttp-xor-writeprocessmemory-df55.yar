rule TTP_XOR_WriteProcessMemory_df55 {
  strings:
    $key_df55 = { 88 27 [2] ba 05 [2] bc 30 [2] 92 30 [2] ad 2c }

  condition:
    any of them
}