rule TTP_XOR_WriteProcessMemory_d3c6 {
  strings:
    $key_d3c6 = { 84 b4 [2] b6 96 [2] b0 a3 [2] 9e a3 [2] a1 bf }

  condition:
    any of them
}