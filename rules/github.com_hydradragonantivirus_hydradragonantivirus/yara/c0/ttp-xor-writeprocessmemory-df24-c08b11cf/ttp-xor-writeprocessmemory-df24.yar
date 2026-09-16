rule TTP_XOR_WriteProcessMemory_df24 {
  strings:
    $key_df24 = { 88 56 [2] ba 74 [2] bc 41 [2] 92 41 [2] ad 5d }

  condition:
    any of them
}