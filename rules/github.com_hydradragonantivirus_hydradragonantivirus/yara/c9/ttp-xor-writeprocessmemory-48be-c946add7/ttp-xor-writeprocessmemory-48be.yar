rule TTP_XOR_WriteProcessMemory_48be {
  strings:
    $key_48be = { 1f cc [2] 2d ee [2] 2b db [2] 05 db [2] 3a c7 }

  condition:
    any of them
}