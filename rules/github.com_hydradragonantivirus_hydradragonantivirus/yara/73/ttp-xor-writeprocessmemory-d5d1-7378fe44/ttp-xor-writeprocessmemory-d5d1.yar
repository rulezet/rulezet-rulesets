rule TTP_XOR_WriteProcessMemory_d5d1 {
  strings:
    $key_d5d1 = { 82 a3 [2] b0 81 [2] b6 b4 [2] 98 b4 [2] a7 a8 }

  condition:
    any of them
}