rule TTP_XOR_WriteProcessMemory_2481 {
  strings:
    $key_2481 = { 73 f3 [2] 41 d1 [2] 47 e4 [2] 69 e4 [2] 56 f8 }

  condition:
    any of them
}