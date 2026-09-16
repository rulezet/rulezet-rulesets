rule TTP_XOR_WriteProcessMemory_62be {
  strings:
    $key_62be = { 35 cc [2] 07 ee [2] 01 db [2] 2f db [2] 10 c7 }

  condition:
    any of them
}