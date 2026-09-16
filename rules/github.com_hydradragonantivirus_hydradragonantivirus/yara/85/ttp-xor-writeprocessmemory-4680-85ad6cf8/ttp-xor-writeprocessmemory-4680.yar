rule TTP_XOR_WriteProcessMemory_4680 {
  strings:
    $key_4680 = { 11 f2 [2] 23 d0 [2] 25 e5 [2] 0b e5 [2] 34 f9 }

  condition:
    any of them
}