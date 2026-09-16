rule TTP_XOR_WriteProcessMemory_d3d6 {
  strings:
    $key_d3d6 = { 84 a4 [2] b6 86 [2] b0 b3 [2] 9e b3 [2] a1 af }

  condition:
    any of them
}