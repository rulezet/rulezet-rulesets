rule TTP_XOR_WriteProcessMemory_df6e {
  strings:
    $key_df6e = { 88 1c [2] ba 3e [2] bc 0b [2] 92 0b [2] ad 17 }

  condition:
    any of them
}