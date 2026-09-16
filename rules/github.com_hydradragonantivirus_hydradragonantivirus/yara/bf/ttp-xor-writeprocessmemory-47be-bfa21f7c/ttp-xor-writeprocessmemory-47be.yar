rule TTP_XOR_WriteProcessMemory_47be {
  strings:
    $key_47be = { 10 cc [2] 22 ee [2] 24 db [2] 0a db [2] 35 c7 }

  condition:
    any of them
}