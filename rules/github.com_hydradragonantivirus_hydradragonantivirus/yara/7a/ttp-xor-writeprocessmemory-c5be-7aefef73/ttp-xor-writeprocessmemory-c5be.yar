rule TTP_XOR_WriteProcessMemory_c5be {
  strings:
    $key_c5be = { 92 cc [2] a0 ee [2] a6 db [2] 88 db [2] b7 c7 }

  condition:
    any of them
}