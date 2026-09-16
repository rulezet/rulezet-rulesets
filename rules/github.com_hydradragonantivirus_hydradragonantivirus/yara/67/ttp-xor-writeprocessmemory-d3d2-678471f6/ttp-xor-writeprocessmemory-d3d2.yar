rule TTP_XOR_WriteProcessMemory_d3d2 {
  strings:
    $key_d3d2 = { 84 a0 [2] b6 82 [2] b0 b7 [2] 9e b7 [2] a1 ab }

  condition:
    any of them
}