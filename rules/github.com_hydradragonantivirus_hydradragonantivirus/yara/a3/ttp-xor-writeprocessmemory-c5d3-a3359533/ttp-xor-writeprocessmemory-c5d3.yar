rule TTP_XOR_WriteProcessMemory_c5d3 {
  strings:
    $key_c5d3 = { 92 a1 [2] a0 83 [2] a6 b6 [2] 88 b6 [2] b7 aa }

  condition:
    any of them
}