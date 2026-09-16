rule TTP_XOR_WriteProcessMemory_df72 {
  strings:
    $key_df72 = { 88 00 [2] ba 22 [2] bc 17 [2] 92 17 [2] ad 0b }

  condition:
    any of them
}