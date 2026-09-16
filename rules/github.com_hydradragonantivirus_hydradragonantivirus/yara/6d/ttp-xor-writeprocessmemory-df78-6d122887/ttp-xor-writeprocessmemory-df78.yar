rule TTP_XOR_WriteProcessMemory_df78 {
  strings:
    $key_df78 = { 88 0a [2] ba 28 [2] bc 1d [2] 92 1d [2] ad 01 }

  condition:
    any of them
}