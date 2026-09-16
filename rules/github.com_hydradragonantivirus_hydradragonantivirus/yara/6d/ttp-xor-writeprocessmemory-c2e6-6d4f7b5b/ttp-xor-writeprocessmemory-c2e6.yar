rule TTP_XOR_WriteProcessMemory_c2e6 {
  strings:
    $key_c2e6 = { 95 94 [2] a7 b6 [2] a1 83 [2] 8f 83 [2] b0 9f }

  condition:
    any of them
}