rule TTP_XOR_WriteProcessMemory_d0be {
  strings:
    $key_d0be = { 87 cc [2] b5 ee [2] b3 db [2] 9d db [2] a2 c7 }

  condition:
    any of them
}