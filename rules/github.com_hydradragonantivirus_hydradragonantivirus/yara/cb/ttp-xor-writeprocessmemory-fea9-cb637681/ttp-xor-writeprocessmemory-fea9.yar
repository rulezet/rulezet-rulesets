rule TTP_XOR_WriteProcessMemory_fea9 {
  strings:
    $key_fea9 = { a9 db [2] 9b f9 [2] 9d cc [2] b3 cc [2] 8c d0 }

  condition:
    any of them
}