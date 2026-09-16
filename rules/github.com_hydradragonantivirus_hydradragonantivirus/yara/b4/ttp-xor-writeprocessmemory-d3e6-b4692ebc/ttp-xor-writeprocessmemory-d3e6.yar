rule TTP_XOR_WriteProcessMemory_d3e6 {
  strings:
    $key_d3e6 = { 84 94 [2] b6 b6 [2] b0 83 [2] 9e 83 [2] a1 9f }

  condition:
    any of them
}