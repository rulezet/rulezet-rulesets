rule TTP_XOR_WriteProcessMemory_df18 {
  strings:
    $key_df18 = { 88 6a [2] ba 48 [2] bc 7d [2] 92 7d [2] ad 61 }

  condition:
    any of them
}