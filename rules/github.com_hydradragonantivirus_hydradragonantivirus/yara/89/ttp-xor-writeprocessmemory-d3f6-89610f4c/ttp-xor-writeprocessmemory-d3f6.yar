rule TTP_XOR_WriteProcessMemory_d3f6 {
  strings:
    $key_d3f6 = { 84 84 [2] b6 a6 [2] b0 93 [2] 9e 93 [2] a1 8f }

  condition:
    any of them
}