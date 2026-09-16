rule TTP_XOR_WriteProcessMemory_55be {
  strings:
    $key_55be = { 02 cc [2] 30 ee [2] 36 db [2] 18 db [2] 27 c7 }

  condition:
    any of them
}