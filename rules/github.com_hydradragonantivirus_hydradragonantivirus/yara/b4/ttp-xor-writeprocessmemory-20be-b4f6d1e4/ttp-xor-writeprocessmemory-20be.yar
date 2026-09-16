rule TTP_XOR_WriteProcessMemory_20be {
  strings:
    $key_20be = { 77 cc [2] 45 ee [2] 43 db [2] 6d db [2] 52 c7 }

  condition:
    any of them
}