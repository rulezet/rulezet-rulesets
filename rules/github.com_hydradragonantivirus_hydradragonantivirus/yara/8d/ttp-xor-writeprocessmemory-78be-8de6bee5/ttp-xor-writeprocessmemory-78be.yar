rule TTP_XOR_WriteProcessMemory_78be {
  strings:
    $key_78be = { 2f cc [2] 1d ee [2] 1b db [2] 35 db [2] 0a c7 }

  condition:
    any of them
}