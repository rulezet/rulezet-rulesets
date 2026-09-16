rule TTP_XOR_WriteProcessMemory_40b0 {
  strings:
    $key_40b0 = { 17 c2 [2] 25 e0 [2] 23 d5 [2] 0d d5 [2] 32 c9 }

  condition:
    any of them
}