rule TTP_XOR_WriteProcessMemory_d3dd {
  strings:
    $key_d3dd = { 84 af [2] b6 8d [2] b0 b8 [2] 9e b8 [2] a1 a4 }

  condition:
    any of them
}