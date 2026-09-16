rule TTP_XOR_WriteProcessMemory_d3f3 {
  strings:
    $key_d3f3 = { 84 81 [2] b6 a3 [2] b0 96 [2] 9e 96 [2] a1 8a }

  condition:
    any of them
}