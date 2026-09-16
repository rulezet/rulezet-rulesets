rule TTP_XOR_WriteProcessMemory_20a0 {
  strings:
    $key_20a0 = { 77 d2 [2] 45 f0 [2] 43 c5 [2] 6d c5 [2] 52 d9 }

  condition:
    any of them
}