rule TTP_XOR_WriteProcessMemory_df33 {
  strings:
    $key_df33 = { 88 41 [2] ba 63 [2] bc 56 [2] 92 56 [2] ad 4a }

  condition:
    any of them
}