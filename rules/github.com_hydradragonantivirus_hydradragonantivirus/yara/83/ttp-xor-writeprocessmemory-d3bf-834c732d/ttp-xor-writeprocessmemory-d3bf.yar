rule TTP_XOR_WriteProcessMemory_d3bf {
  strings:
    $key_d3bf = { 84 cd [2] b6 ef [2] b0 da [2] 9e da [2] a1 c6 }

  condition:
    any of them
}