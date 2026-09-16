rule TTP_XOR_WriteProcessMemory_d6d4 {
  strings:
    $key_d6d4 = { 81 a6 [2] b3 84 [2] b5 b1 [2] 9b b1 [2] a4 ad }

  condition:
    any of them
}