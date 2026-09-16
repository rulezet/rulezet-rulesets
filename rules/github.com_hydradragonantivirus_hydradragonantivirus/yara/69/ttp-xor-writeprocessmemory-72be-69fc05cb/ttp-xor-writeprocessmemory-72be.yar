rule TTP_XOR_WriteProcessMemory_72be {
  strings:
    $key_72be = { 25 cc [2] 17 ee [2] 11 db [2] 3f db [2] 00 c7 }

  condition:
    any of them
}