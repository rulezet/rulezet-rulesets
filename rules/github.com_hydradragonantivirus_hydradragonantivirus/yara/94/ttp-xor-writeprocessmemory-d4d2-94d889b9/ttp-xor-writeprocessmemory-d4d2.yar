rule TTP_XOR_WriteProcessMemory_d4d2 {
  strings:
    $key_d4d2 = { 83 a0 [2] b1 82 [2] b7 b7 [2] 99 b7 [2] a6 ab }

  condition:
    any of them
}