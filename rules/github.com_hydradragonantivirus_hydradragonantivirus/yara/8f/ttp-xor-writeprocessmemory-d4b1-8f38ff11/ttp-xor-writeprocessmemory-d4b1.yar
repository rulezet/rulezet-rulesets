rule TTP_XOR_WriteProcessMemory_d4b1 {
  strings:
    $key_d4b1 = { 83 c3 [2] b1 e1 [2] b7 d4 [2] 99 d4 [2] a6 c8 }

  condition:
    any of them
}