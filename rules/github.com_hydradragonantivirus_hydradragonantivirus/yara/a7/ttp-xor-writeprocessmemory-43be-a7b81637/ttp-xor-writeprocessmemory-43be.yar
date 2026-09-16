rule TTP_XOR_WriteProcessMemory_43be {
  strings:
    $key_43be = { 14 cc [2] 26 ee [2] 20 db [2] 0e db [2] 31 c7 }

  condition:
    any of them
}