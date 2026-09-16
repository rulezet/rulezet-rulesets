rule TTP_XOR_WriteProcessMemory_d5d2 {
  strings:
    $key_d5d2 = { 82 a0 [2] b0 82 [2] b6 b7 [2] 98 b7 [2] a7 ab }

  condition:
    any of them
}