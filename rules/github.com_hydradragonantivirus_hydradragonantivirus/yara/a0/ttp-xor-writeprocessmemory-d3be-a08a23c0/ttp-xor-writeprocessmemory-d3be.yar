rule TTP_XOR_WriteProcessMemory_d3be {
  strings:
    $key_d3be = { 84 cc [2] b6 ee [2] b0 db [2] 9e db [2] a1 c7 }

  condition:
    any of them
}