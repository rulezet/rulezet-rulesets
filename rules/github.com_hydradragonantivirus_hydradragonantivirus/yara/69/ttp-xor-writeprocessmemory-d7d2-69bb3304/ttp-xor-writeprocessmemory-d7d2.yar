rule TTP_XOR_WriteProcessMemory_d7d2 {
  strings:
    $key_d7d2 = { 80 a0 [2] b2 82 [2] b4 b7 [2] 9a b7 [2] a5 ab }

  condition:
    any of them
}