rule TTP_XOR_WriteProcessMemory_d5f1 {
  strings:
    $key_d5f1 = { 82 83 [2] b0 a1 [2] b6 94 [2] 98 94 [2] a7 88 }

  condition:
    any of them
}