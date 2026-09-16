rule TTP_XOR_WriteProcessMemory_d2f1 {
  strings:
    $key_d2f1 = { 85 83 [2] b7 a1 [2] b1 94 [2] 9f 94 [2] a0 88 }

  condition:
    any of them
}