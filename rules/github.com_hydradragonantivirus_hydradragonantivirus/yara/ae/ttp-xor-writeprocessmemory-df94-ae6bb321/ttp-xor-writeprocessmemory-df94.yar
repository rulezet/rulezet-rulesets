rule TTP_XOR_WriteProcessMemory_df94 {
  strings:
    $key_df94 = { 88 e6 [2] ba c4 [2] bc f1 [2] 92 f1 [2] ad ed }

  condition:
    any of them
}