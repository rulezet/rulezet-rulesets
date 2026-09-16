rule TTP_XOR_WriteProcessMemory_df7d {
  strings:
    $key_df7d = { 88 0f [2] ba 2d [2] bc 18 [2] 92 18 [2] ad 04 }

  condition:
    any of them
}