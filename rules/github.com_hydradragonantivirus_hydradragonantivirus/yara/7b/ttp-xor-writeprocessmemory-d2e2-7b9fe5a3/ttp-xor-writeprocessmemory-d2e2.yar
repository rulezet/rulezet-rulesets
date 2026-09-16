rule TTP_XOR_WriteProcessMemory_d2e2 {
  strings:
    $key_d2e2 = { 85 90 [2] b7 b2 [2] b1 87 [2] 9f 87 [2] a0 9b }

  condition:
    any of them
}