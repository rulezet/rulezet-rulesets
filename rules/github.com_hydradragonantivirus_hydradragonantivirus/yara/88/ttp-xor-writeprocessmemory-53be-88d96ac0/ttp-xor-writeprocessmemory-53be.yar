rule TTP_XOR_WriteProcessMemory_53be {
  strings:
    $key_53be = { 04 cc [2] 36 ee [2] 30 db [2] 1e db [2] 21 c7 }

  condition:
    any of them
}