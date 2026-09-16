rule TTP_XOR_WriteProcessMemory_df9a {
  strings:
    $key_df9a = { 88 e8 [2] ba ca [2] bc ff [2] 92 ff [2] ad e3 }

  condition:
    any of them
}