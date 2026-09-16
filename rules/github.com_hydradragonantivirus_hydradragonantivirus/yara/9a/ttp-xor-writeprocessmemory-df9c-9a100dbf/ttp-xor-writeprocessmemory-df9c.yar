rule TTP_XOR_WriteProcessMemory_df9c {
  strings:
    $key_df9c = { 88 ee [2] ba cc [2] bc f9 [2] 92 f9 [2] ad e5 }

  condition:
    any of them
}