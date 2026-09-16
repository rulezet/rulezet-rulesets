rule TTP_XOR_WriteProcessMemory_d3d9 {
  strings:
    $key_d3d9 = { 84 ab [2] b6 89 [2] b0 bc [2] 9e bc [2] a1 a0 }

  condition:
    any of them
}