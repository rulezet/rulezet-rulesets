rule TTP_XOR_WriteProcessMemory_64a9 {
  strings:
    $key_64a9 = { 33 db [2] 01 f9 [2] 07 cc [2] 29 cc [2] 16 d0 }

  condition:
    any of them
}