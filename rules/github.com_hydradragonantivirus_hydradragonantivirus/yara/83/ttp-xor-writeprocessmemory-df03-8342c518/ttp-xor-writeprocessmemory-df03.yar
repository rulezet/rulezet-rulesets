rule TTP_XOR_WriteProcessMemory_df03 {
  strings:
    $key_df03 = { 88 71 [2] ba 53 [2] bc 66 [2] 92 66 [2] ad 7a }

  condition:
    any of them
}