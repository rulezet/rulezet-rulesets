rule TTP_XOR_WriteProcessMemory_40a0 {
  strings:
    $key_40a0 = { 17 d2 [2] 25 f0 [2] 23 c5 [2] 0d c5 [2] 32 d9 }

  condition:
    any of them
}