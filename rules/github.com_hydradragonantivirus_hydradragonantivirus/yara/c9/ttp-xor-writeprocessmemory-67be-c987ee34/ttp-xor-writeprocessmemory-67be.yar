rule TTP_XOR_WriteProcessMemory_67be {
  strings:
    $key_67be = { 30 cc [2] 02 ee [2] 04 db [2] 2a db [2] 15 c7 }

  condition:
    any of them
}