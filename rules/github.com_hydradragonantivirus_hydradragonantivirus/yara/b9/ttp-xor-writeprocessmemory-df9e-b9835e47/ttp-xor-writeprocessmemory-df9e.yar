rule TTP_XOR_WriteProcessMemory_df9e {
  strings:
    $key_df9e = { 88 ec [2] ba ce [2] bc fb [2] 92 fb [2] ad e7 }

  condition:
    any of them
}