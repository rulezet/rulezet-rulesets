rule TTP_XOR_WriteProcessMemory_df3e {
  strings:
    $key_df3e = { 88 4c [2] ba 6e [2] bc 5b [2] 92 5b [2] ad 47 }

  condition:
    any of them
}