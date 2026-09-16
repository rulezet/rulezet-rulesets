rule TTP_XOR_WriteProcessMemory_d4b6 {
  strings:
    $key_d4b6 = { 83 c4 [2] b1 e6 [2] b7 d3 [2] 99 d3 [2] a6 cf }

  condition:
    any of them
}