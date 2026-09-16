rule TTP_XOR_WriteProcessMemory_59be {
  strings:
    $key_59be = { 0e cc [2] 3c ee [2] 3a db [2] 14 db [2] 2b c7 }

  condition:
    any of them
}