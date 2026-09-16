rule TTP_XOR_WriteProcessMemory_d3b9 {
  strings:
    $key_d3b9 = { 84 cb [2] b6 e9 [2] b0 dc [2] 9e dc [2] a1 c0 }

  condition:
    any of them
}