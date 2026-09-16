rule TTP_XOR_WriteProcessMemory_c780 {
  strings:
    $key_c780 = { 90 f2 [2] a2 d0 [2] a4 e5 [2] 8a e5 [2] b5 f9 }

  condition:
    any of them
}