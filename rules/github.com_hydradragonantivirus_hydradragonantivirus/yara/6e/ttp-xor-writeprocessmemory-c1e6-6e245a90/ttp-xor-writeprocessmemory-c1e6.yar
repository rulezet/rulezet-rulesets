rule TTP_XOR_WriteProcessMemory_c1e6 {
  strings:
    $key_c1e6 = { 96 94 [2] a4 b6 [2] a2 83 [2] 8c 83 [2] b3 9f }

  condition:
    any of them
}