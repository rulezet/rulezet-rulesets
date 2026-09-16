rule TTP_XOR_WriteProcessMemory_df80 {
  strings:
    $key_df80 = { 88 f2 [2] ba d0 [2] bc e5 [2] 92 e5 [2] ad f9 }

  condition:
    any of them
}