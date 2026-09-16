rule TTP_XOR_WriteProcessMemory_d2d3 {
  strings:
    $key_d2d3 = { 85 a1 [2] b7 83 [2] b1 b6 [2] 9f b6 [2] a0 aa }

  condition:
    any of them
}