rule TTP_XOR_WriteProcessMemory_df2f {
  strings:
    $key_df2f = { 88 5d [2] ba 7f [2] bc 4a [2] 92 4a [2] ad 56 }

  condition:
    any of them
}