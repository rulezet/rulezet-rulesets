rule TTP_XOR_WriteProcessMemory_c436 {
  strings:
    $key_c436 = { 93 44 [2] a1 66 [2] a7 53 [2] 89 53 [2] b6 4f }

  condition:
    any of them
}