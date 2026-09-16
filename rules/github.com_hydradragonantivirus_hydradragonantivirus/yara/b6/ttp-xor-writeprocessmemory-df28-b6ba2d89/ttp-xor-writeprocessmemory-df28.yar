rule TTP_XOR_WriteProcessMemory_df28 {
  strings:
    $key_df28 = { 88 5a [2] ba 78 [2] bc 4d [2] 92 4d [2] ad 51 }

  condition:
    any of them
}