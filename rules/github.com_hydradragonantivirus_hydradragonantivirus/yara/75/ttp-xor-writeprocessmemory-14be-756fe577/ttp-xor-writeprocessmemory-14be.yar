rule TTP_XOR_WriteProcessMemory_14be {
  strings:
    $key_14be = { 43 cc [2] 71 ee [2] 77 db [2] 59 db [2] 66 c7 }

  condition:
    any of them
}