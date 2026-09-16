rule TTP_XOR_WriteProcessMemory_77be {
  strings:
    $key_77be = { 20 cc [2] 12 ee [2] 14 db [2] 3a db [2] 05 c7 }

  condition:
    any of them
}