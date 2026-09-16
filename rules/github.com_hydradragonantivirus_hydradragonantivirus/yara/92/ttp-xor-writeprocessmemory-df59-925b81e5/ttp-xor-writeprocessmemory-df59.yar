rule TTP_XOR_WriteProcessMemory_df59 {
  strings:
    $key_df59 = { 88 2b [2] ba 09 [2] bc 3c [2] 92 3c [2] ad 20 }

  condition:
    any of them
}