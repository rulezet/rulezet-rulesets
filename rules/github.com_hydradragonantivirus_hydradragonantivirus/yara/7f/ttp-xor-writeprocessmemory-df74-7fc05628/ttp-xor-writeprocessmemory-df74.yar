rule TTP_XOR_WriteProcessMemory_df74 {
  strings:
    $key_df74 = { 88 06 [2] ba 24 [2] bc 11 [2] 92 11 [2] ad 0d }

  condition:
    any of them
}