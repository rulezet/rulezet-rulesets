rule TTP_XOR_WriteProcessMemory_c5f6 {
  strings:
    $key_c5f6 = { 92 84 [2] a0 a6 [2] a6 93 [2] 88 93 [2] b7 8f }

  condition:
    any of them
}