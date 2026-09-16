rule TTP_XOR_WriteProcessMemory_18be {
  strings:
    $key_18be = { 4f cc [2] 7d ee [2] 7b db [2] 55 db [2] 6a c7 }

  condition:
    any of them
}