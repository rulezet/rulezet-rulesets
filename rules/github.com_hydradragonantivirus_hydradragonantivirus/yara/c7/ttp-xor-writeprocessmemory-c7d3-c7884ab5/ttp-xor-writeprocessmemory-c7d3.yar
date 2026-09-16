rule TTP_XOR_WriteProcessMemory_c7d3 {
  strings:
    $key_c7d3 = { 90 a1 [2] a2 83 [2] a4 b6 [2] 8a b6 [2] b5 aa }

  condition:
    any of them
}