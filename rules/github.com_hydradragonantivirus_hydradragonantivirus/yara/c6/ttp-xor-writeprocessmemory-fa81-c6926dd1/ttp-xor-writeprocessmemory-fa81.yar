rule TTP_XOR_WriteProcessMemory_fa81 {
  strings:
    $key_fa81 = { ad f3 [2] 9f d1 [2] 99 e4 [2] b7 e4 [2] 88 f8 }

  condition:
    any of them
}