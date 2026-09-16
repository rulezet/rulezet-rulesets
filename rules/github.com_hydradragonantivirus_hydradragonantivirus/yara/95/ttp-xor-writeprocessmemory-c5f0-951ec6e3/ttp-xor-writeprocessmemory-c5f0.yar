rule TTP_XOR_WriteProcessMemory_c5f0 {
  strings:
    $key_c5f0 = { 92 82 [2] a0 a0 [2] a6 95 [2] 88 95 [2] b7 89 }

  condition:
    any of them
}