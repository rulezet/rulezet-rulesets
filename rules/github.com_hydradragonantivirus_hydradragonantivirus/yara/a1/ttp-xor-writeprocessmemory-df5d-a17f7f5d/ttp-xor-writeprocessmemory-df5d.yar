rule TTP_XOR_WriteProcessMemory_df5d {
  strings:
    $key_df5d = { 88 2f [2] ba 0d [2] bc 38 [2] 92 38 [2] ad 24 }

  condition:
    any of them
}