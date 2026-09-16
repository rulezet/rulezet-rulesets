rule TTP_XOR_WriteProcessMemory_c1be {
  strings:
    $key_c1be = { 96 cc [2] a4 ee [2] a2 db [2] 8c db [2] b3 c7 }

  condition:
    any of them
}