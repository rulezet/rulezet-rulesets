rule TTP_XOR_WriteProcessMemory_d5c1 {
  strings:
    $key_d5c1 = { 82 b3 [2] b0 91 [2] b6 a4 [2] 98 a4 [2] a7 b8 }

  condition:
    any of them
}