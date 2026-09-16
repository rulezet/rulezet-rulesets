rule TTP_XOR_WriteProcessMemory_50a0 {
  strings:
    $key_50a0 = { 07 d2 [2] 35 f0 [2] 33 c5 [2] 1d c5 [2] 22 d9 }

  condition:
    any of them
}