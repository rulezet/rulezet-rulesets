rule TTP_XOR_WriteProcessMemory_44be {
  strings:
    $key_44be = { 13 cc [2] 21 ee [2] 27 db [2] 09 db [2] 36 c7 }

  condition:
    any of them
}