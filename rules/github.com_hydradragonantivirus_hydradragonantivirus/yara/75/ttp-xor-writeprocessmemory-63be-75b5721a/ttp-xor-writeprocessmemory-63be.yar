rule TTP_XOR_WriteProcessMemory_63be {
  strings:
    $key_63be = { 34 cc [2] 06 ee [2] 00 db [2] 2e db [2] 11 c7 }

  condition:
    any of them
}