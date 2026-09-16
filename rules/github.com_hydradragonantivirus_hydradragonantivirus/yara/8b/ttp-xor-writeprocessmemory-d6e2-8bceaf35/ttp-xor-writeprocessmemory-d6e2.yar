rule TTP_XOR_WriteProcessMemory_d6e2 {
  strings:
    $key_d6e2 = { 81 90 [2] b3 b2 [2] b5 87 [2] 9b 87 [2] a4 9b }

  condition:
    any of them
}