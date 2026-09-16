rule TTP_XOR_WriteProcessMemory_23be {
  strings:
    $key_23be = { 74 cc [2] 46 ee [2] 40 db [2] 6e db [2] 51 c7 }

  condition:
    any of them
}