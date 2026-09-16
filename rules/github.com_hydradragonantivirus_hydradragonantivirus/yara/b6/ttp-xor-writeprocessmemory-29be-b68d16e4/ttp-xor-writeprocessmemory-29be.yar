rule TTP_XOR_WriteProcessMemory_29be {
  strings:
    $key_29be = { 7e cc [2] 4c ee [2] 4a db [2] 64 db [2] 5b c7 }

  condition:
    any of them
}