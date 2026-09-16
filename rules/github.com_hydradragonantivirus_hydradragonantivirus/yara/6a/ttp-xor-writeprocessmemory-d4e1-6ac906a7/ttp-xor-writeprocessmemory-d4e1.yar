rule TTP_XOR_WriteProcessMemory_d4e1 {
  strings:
    $key_d4e1 = { 83 93 [2] b1 b1 [2] b7 84 [2] 99 84 [2] a6 98 }

  condition:
    any of them
}