rule TTP_XOR_WriteProcessMemory_df98 {
  strings:
    $key_df98 = { 88 ea [2] ba c8 [2] bc fd [2] 92 fd [2] ad e1 }

  condition:
    any of them
}