rule TTP_XOR_WriteProcessMemory_d4f6 {
  strings:
    $key_d4f6 = { 83 84 [2] b1 a6 [2] b7 93 [2] 99 93 [2] a6 8f }

  condition:
    any of them
}