rule TTP_XOR_WriteProcessMemory_08be {
  strings:
    $key_08be = { 5f cc [2] 6d ee [2] 6b db [2] 45 db [2] 7a c7 }

  condition:
    any of them
}