rule TTP_XOR_WriteProcessMemory_30b1 {
  strings:
    $key_30b1 = { 67 c3 [2] 55 e1 [2] 53 d4 [2] 7d d4 [2] 42 c8 }

  condition:
    any of them
}