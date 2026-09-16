rule TTP_XOR_WriteProcessMemory_73be {
  strings:
    $key_73be = { 24 cc [2] 16 ee [2] 10 db [2] 3e db [2] 01 c7 }

  condition:
    any of them
}