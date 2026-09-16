rule TTP_XOR_WriteProcessMemory_df75 {
  strings:
    $key_df75 = { 88 07 [2] ba 25 [2] bc 10 [2] 92 10 [2] ad 0c }

  condition:
    any of them
}