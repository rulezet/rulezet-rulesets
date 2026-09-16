rule TTP_XOR_WriteProcessMemory_df31 {
  strings:
    $key_df31 = { 88 43 [2] ba 61 [2] bc 54 [2] 92 54 [2] ad 48 }

  condition:
    any of them
}