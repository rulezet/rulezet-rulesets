rule TTP_XOR_WriteProcessMemory_df81 {
  strings:
    $key_df81 = { 88 f3 [2] ba d1 [2] bc e4 [2] 92 e4 [2] ad f8 }

  condition:
    any of them
}