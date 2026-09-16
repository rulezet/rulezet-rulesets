rule TTP_XOR_WriteProcessMemory_17be {
  strings:
    $key_17be = { 40 cc [2] 72 ee [2] 74 db [2] 5a db [2] 65 c7 }

  condition:
    any of them
}