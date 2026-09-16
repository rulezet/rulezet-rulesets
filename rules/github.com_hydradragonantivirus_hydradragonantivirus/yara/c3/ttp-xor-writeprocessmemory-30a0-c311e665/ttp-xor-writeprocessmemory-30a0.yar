rule TTP_XOR_WriteProcessMemory_30a0 {
  strings:
    $key_30a0 = { 67 d2 [2] 55 f0 [2] 53 c5 [2] 7d c5 [2] 42 d9 }

  condition:
    any of them
}