rule TTP_XOR_WriteProcessMemory_d3d5 {
  strings:
    $key_d3d5 = { 84 a7 [2] b6 85 [2] b0 b0 [2] 9e b0 [2] a1 ac }

  condition:
    any of them
}