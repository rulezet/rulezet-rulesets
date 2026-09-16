rule TTP_XOR_WriteProcessMemory_d5e2 {
  strings:
    $key_d5e2 = { 82 90 [2] b0 b2 [2] b6 87 [2] 98 87 [2] a7 9b }

  condition:
    any of them
}