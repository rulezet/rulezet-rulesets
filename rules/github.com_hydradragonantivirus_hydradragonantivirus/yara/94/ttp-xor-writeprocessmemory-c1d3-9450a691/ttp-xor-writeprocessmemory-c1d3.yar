rule TTP_XOR_WriteProcessMemory_c1d3 {
  strings:
    $key_c1d3 = { 96 a1 [2] a4 83 [2] a2 b6 [2] 8c b6 [2] b3 aa }

  condition:
    any of them
}