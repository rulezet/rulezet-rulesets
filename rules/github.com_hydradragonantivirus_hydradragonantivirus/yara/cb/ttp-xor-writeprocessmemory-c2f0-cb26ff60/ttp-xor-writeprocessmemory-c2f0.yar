rule TTP_XOR_WriteProcessMemory_c2f0 {
  strings:
    $key_c2f0 = { 95 82 [2] a7 a0 [2] a1 95 [2] 8f 95 [2] b0 89 }

  condition:
    any of them
}