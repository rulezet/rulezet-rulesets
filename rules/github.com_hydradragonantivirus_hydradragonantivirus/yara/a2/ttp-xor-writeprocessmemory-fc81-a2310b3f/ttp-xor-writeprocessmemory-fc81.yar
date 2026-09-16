rule TTP_XOR_WriteProcessMemory_fc81 {
  strings:
    $key_fc81 = { ab f3 [2] 99 d1 [2] 9f e4 [2] b1 e4 [2] 8e f8 }

  condition:
    any of them
}