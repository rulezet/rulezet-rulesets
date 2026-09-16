rule TTP_XOR_WriteProcessMemory_c2e2 {
  strings:
    $key_c2e2 = { 95 90 [2] a7 b2 [2] a1 87 [2] 8f 87 [2] b0 9b }

  condition:
    any of them
}