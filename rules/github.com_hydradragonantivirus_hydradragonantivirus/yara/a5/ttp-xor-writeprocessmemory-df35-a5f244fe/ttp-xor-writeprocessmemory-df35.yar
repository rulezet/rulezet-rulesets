rule TTP_XOR_WriteProcessMemory_df35 {
  strings:
    $key_df35 = { 88 47 [2] ba 65 [2] bc 50 [2] 92 50 [2] ad 4c }

  condition:
    any of them
}