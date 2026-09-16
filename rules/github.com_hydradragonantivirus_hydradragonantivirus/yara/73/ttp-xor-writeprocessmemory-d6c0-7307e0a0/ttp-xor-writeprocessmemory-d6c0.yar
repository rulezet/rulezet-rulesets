rule TTP_XOR_WriteProcessMemory_d6c0 {
  strings:
    $key_d6c0 = { 81 b2 [2] b3 90 [2] b5 a5 [2] 9b a5 [2] a4 b9 }

  condition:
    any of them
}