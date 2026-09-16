rule TTP_XOR_WriteProcessMemory_c1e0 {
  strings:
    $key_c1e0 = { 96 92 [2] a4 b0 [2] a2 85 [2] 8c 85 [2] b3 99 }

  condition:
    any of them
}