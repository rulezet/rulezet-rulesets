rule TTP_XOR_WriteProcessMemory_d3f8 {
  strings:
    $key_d3f8 = { 84 8a [2] b6 a8 [2] b0 9d [2] 9e 9d [2] a1 81 }

  condition:
    any of them
}