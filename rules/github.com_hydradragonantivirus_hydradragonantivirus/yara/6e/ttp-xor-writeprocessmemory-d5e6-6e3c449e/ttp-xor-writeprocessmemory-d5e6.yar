rule TTP_XOR_WriteProcessMemory_d5e6 {
  strings:
    $key_d5e6 = { 82 94 [2] b0 b6 [2] b6 83 [2] 98 83 [2] a7 9f }

  condition:
    any of them
}