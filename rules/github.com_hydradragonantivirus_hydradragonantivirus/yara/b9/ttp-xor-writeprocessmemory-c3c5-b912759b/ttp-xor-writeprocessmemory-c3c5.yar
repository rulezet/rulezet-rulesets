rule TTP_XOR_WriteProcessMemory_c3c5 {
  strings:
    $key_c3c5 = { 94 b7 [2] a6 95 [2] a0 a0 [2] 8e a0 [2] b1 bc }

  condition:
    any of them
}