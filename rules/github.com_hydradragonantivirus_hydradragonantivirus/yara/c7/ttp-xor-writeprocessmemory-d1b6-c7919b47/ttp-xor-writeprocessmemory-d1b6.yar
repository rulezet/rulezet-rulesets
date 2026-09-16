rule TTP_XOR_WriteProcessMemory_d1b6 {
  strings:
    $key_d1b6 = { 86 c4 [2] b4 e6 [2] b2 d3 [2] 9c d3 [2] a3 cf }

  condition:
    any of them
}