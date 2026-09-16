rule TTP_XOR_WriteProcessMemory_df93 {
  strings:
    $key_df93 = { 88 e1 [2] ba c3 [2] bc f6 [2] 92 f6 [2] ad ea }

  condition:
    any of them
}