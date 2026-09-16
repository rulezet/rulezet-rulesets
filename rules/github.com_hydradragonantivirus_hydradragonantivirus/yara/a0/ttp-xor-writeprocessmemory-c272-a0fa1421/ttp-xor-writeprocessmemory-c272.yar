rule TTP_XOR_WriteProcessMemory_c272 {
  strings:
    $key_c272 = { 95 00 [2] a7 22 [2] a1 17 [2] 8f 17 [2] b0 0b }

  condition:
    any of them
}