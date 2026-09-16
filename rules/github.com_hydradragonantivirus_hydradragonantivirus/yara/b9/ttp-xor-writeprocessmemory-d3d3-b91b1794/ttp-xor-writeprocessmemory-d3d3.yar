rule TTP_XOR_WriteProcessMemory_d3d3 {
  strings:
    $key_d3d3 = { 84 a1 [2] b6 83 [2] b0 b6 [2] 9e b6 [2] a1 aa }

  condition:
    any of them
}