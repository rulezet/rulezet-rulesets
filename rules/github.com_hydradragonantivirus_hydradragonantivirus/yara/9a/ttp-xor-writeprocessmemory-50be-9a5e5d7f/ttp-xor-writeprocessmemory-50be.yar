rule TTP_XOR_WriteProcessMemory_50be {
  strings:
    $key_50be = { 07 cc [2] 35 ee [2] 33 db [2] 1d db [2] 22 c7 }

  condition:
    any of them
}