rule TTP_XOR_WriteProcessMemory_d481 {
  strings:
    $key_d481 = { 83 f3 [2] b1 d1 [2] b7 e4 [2] 99 e4 [2] a6 f8 }

  condition:
    any of them
}