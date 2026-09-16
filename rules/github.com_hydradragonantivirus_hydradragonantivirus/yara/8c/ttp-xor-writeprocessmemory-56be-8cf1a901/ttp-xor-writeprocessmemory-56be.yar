rule TTP_XOR_WriteProcessMemory_56be {
  strings:
    $key_56be = { 01 cc [2] 33 ee [2] 35 db [2] 1b db [2] 24 c7 }

  condition:
    any of them
}