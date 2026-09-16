rule TTP_XOR_WriteProcessMemory_c2b6 {
  strings:
    $key_c2b6 = { 95 c4 [2] a7 e6 [2] a1 d3 [2] 8f d3 [2] b0 cf }

  condition:
    any of them
}