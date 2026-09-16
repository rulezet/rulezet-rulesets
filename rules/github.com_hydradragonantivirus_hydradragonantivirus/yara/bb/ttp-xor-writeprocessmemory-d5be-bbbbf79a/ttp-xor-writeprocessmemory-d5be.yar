rule TTP_XOR_WriteProcessMemory_d5be {
  strings:
    $key_d5be = { 82 cc [2] b0 ee [2] b6 db [2] 98 db [2] a7 c7 }

  condition:
    any of them
}