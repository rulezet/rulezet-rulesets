rule TTP_XOR_WriteProcessMemory_40b1 {
  strings:
    $key_40b1 = { 17 c3 [2] 25 e1 [2] 23 d4 [2] 0d d4 [2] 32 c8 }

  condition:
    any of them
}