rule TTP_XOR_WriteProcessMemory_4780 {
  strings:
    $key_4780 = { 10 f2 [2] 22 d0 [2] 24 e5 [2] 0a e5 [2] 35 f9 }

  condition:
    any of them
}