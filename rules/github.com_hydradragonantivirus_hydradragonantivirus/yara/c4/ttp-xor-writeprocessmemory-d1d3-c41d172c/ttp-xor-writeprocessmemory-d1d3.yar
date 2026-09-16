rule TTP_XOR_WriteProcessMemory_d1d3 {
  strings:
    $key_d1d3 = { 86 a1 [2] b4 83 [2] b2 b6 [2] 9c b6 [2] a3 aa }

  condition:
    any of them
}