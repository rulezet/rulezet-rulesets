rule TTP_XOR_WriteProcessMemory_d5c5 {
  strings:
    $key_d5c5 = { 82 b7 [2] b0 95 [2] b6 a0 [2] 98 a0 [2] a7 bc }

  condition:
    any of them
}