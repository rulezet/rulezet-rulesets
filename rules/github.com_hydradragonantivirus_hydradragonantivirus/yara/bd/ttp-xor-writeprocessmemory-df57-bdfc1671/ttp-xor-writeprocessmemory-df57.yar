rule TTP_XOR_WriteProcessMemory_df57 {
  strings:
    $key_df57 = { 88 25 [2] ba 07 [2] bc 32 [2] 92 32 [2] ad 2e }

  condition:
    any of them
}