rule TTP_XOR_WriteProcessMemory_f680 {
  strings:
    $key_f680 = { a1 f2 [2] 93 d0 [2] 95 e5 [2] bb e5 [2] 84 f9 }

  condition:
    any of them
}