rule TTP_XOR_WriteProcessMemory_c4f6 {
  strings:
    $key_c4f6 = { 93 84 [2] a1 a6 [2] a7 93 [2] 89 93 [2] b6 8f }

  condition:
    any of them
}