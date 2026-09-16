rule TTP_XOR_WriteProcessMemory_c4d3 {
  strings:
    $key_c4d3 = { 93 a1 [2] a1 83 [2] a7 b6 [2] 89 b6 [2] b6 aa }

  condition:
    any of them
}