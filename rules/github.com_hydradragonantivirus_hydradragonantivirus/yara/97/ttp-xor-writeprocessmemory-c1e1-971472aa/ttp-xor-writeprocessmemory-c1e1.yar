rule TTP_XOR_WriteProcessMemory_c1e1 {
  strings:
    $key_c1e1 = { 96 93 [2] a4 b1 [2] a2 84 [2] 8c 84 [2] b3 98 }

  condition:
    any of them
}