rule TTP_XOR_WriteProcessMemory_df07 {
  strings:
    $key_df07 = { 88 75 [2] ba 57 [2] bc 62 [2] 92 62 [2] ad 7e }

  condition:
    any of them
}