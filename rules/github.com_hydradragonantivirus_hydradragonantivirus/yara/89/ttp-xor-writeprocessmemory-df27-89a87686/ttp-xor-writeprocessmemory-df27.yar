rule TTP_XOR_WriteProcessMemory_df27 {
  strings:
    $key_df27 = { 88 55 [2] ba 77 [2] bc 42 [2] 92 42 [2] ad 5e }

  condition:
    any of them
}