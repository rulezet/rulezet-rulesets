rule TTP_XOR_WriteProcessMemory_75be {
  strings:
    $key_75be = { 22 cc [2] 10 ee [2] 16 db [2] 38 db [2] 07 c7 }

  condition:
    any of them
}