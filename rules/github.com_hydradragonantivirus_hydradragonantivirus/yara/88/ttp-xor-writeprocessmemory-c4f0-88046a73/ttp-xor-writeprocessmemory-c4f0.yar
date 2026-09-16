rule TTP_XOR_WriteProcessMemory_c4f0 {
  strings:
    $key_c4f0 = { 93 82 [2] a1 a0 [2] a7 95 [2] 89 95 [2] b6 89 }

  condition:
    any of them
}