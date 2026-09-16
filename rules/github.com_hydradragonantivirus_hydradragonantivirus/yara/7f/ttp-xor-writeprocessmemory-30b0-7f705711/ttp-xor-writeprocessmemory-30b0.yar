rule TTP_XOR_WriteProcessMemory_30b0 {
  strings:
    $key_30b0 = { 67 c2 [2] 55 e0 [2] 53 d5 [2] 7d d5 [2] 42 c9 }

  condition:
    any of them
}