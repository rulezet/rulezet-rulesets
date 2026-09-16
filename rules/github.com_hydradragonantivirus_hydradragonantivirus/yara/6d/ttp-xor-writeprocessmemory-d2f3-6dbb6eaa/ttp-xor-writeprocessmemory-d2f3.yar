rule TTP_XOR_WriteProcessMemory_d2f3 {
  strings:
    $key_d2f3 = { 85 81 [2] b7 a3 [2] b1 96 [2] 9f 96 [2] a0 8a }

  condition:
    any of them
}