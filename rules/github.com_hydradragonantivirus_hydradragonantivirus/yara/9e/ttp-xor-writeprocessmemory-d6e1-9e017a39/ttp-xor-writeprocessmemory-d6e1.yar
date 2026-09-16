rule TTP_XOR_WriteProcessMemory_d6e1 {
  strings:
    $key_d6e1 = { 81 93 [2] b3 b1 [2] b5 84 [2] 9b 84 [2] a4 98 }

  condition:
    any of them
}