rule TTP_XOR_WriteProcessMemory_d2f0 {
  strings:
    $key_d2f0 = { 85 82 [2] b7 a0 [2] b1 95 [2] 9f 95 [2] a0 89 }

  condition:
    any of them
}