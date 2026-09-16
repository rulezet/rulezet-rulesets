rule TTP_XOR_WriteProcessMemory_c2e1 {
  strings:
    $key_c2e1 = { 95 93 [2] a7 b1 [2] a1 84 [2] 8f 84 [2] b0 98 }

  condition:
    any of them
}