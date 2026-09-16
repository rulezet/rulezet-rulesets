rule TTP_XOR_WriteProcessMemory_df8e {
  strings:
    $key_df8e = { 88 fc [2] ba de [2] bc eb [2] 92 eb [2] ad f7 }

  condition:
    any of them
}