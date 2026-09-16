rule TTP_XOR_WriteProcessMemory_d3a2 {
  strings:
    $key_d3a2 = { 84 d0 [2] b6 f2 [2] b0 c7 [2] 9e c7 [2] a1 db }

  condition:
    any of them
}