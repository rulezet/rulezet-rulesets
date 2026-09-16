rule TTP_XOR_WriteProcessMemory_d4f0 {
  strings:
    $key_d4f0 = { 83 82 [2] b1 a0 [2] b7 95 [2] 99 95 [2] a6 89 }

  condition:
    any of them
}