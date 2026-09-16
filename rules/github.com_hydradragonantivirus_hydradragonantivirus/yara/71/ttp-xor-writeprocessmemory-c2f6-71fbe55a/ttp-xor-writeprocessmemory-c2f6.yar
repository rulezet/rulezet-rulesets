rule TTP_XOR_WriteProcessMemory_c2f6 {
  strings:
    $key_c2f6 = { 95 84 [2] a7 a6 [2] a1 93 [2] 8f 93 [2] b0 8f }

  condition:
    any of them
}