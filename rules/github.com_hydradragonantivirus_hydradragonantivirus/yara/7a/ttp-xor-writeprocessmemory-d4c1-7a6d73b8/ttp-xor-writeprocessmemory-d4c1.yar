rule TTP_XOR_WriteProcessMemory_d4c1 {
  strings:
    $key_d4c1 = { 83 b3 [2] b1 91 [2] b7 a4 [2] 99 a4 [2] a6 b8 }

  condition:
    any of them
}