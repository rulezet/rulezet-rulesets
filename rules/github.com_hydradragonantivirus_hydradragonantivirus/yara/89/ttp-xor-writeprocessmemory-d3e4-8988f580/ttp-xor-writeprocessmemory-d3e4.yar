rule TTP_XOR_WriteProcessMemory_d3e4 {
  strings:
    $key_d3e4 = { 84 96 [2] b6 b4 [2] b0 81 [2] 9e 81 [2] a1 9d }

  condition:
    any of them
}