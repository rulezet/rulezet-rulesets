rule TTP_XOR_WriteProcessMemory_df62 {
  strings:
    $key_df62 = { 88 10 [2] ba 32 [2] bc 07 [2] 92 07 [2] ad 1b }

  condition:
    any of them
}