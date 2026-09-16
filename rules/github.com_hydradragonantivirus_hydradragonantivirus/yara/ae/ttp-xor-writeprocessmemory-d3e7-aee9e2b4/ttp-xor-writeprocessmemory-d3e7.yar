rule TTP_XOR_WriteProcessMemory_d3e7 {
  strings:
    $key_d3e7 = { 84 95 [2] b6 b7 [2] b0 82 [2] 9e 82 [2] a1 9e }

  condition:
    any of them
}