rule TTP_XOR_WriteProcessMemory_df84 {
  strings:
    $key_df84 = { 88 f6 [2] ba d4 [2] bc e1 [2] 92 e1 [2] ad fd }

  condition:
    any of them
}