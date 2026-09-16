rule TTP_XOR_WriteProcessMemory_c200 {
  strings:
    $key_c200 = { 95 72 [2] a7 50 [2] a1 65 [2] 8f 65 [2] b0 79 }

  condition:
    any of them
}