rule TTP_XOR_WriteProcessMemory_df7c {
  strings:
    $key_df7c = { 88 0e [2] ba 2c [2] bc 19 [2] 92 19 [2] ad 05 }

  condition:
    any of them
}