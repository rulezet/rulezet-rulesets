rule TTP_XOR_WriteProcessMemory_cf8e {
  strings:
    $key_cf8e = { 98 fc [2] aa de [2] ac eb [2] 82 eb [2] bd f7 }

  condition:
    any of them
}