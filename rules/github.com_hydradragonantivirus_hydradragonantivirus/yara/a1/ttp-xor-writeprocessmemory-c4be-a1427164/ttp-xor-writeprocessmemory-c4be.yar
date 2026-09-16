rule TTP_XOR_WriteProcessMemory_c4be {
  strings:
    $key_c4be = { 93 cc [2] a1 ee [2] a7 db [2] 89 db [2] b6 c7 }

  condition:
    any of them
}