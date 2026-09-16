rule TTP_XOR_WriteProcessMemory_c150 {
  strings:
    $key_c150 = { 96 22 [2] a4 00 [2] a2 35 [2] 8c 35 [2] b3 29 }

  condition:
    any of them
}