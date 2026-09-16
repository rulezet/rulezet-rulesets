rule TTP_XOR_WriteProcessMemory_df5c {
  strings:
    $key_df5c = { 88 2e [2] ba 0c [2] bc 39 [2] 92 39 [2] ad 25 }

  condition:
    any of them
}