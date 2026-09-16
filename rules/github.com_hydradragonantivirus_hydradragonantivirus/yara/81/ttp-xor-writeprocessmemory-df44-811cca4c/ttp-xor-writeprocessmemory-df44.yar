rule TTP_XOR_WriteProcessMemory_df44 {
  strings:
    $key_df44 = { 88 36 [2] ba 14 [2] bc 21 [2] 92 21 [2] ad 3d }

  condition:
    any of them
}