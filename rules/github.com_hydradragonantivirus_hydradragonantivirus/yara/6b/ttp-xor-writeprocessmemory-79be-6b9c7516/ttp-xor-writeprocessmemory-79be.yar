rule TTP_XOR_WriteProcessMemory_79be {
  strings:
    $key_79be = { 2e cc [2] 1c ee [2] 1a db [2] 34 db [2] 0b c7 }

  condition:
    any of them
}