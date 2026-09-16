rule TTP_XOR_WriteProcessMemory_50b1 {
  strings:
    $key_50b1 = { 07 c3 [2] 35 e1 [2] 33 d4 [2] 1d d4 [2] 22 c8 }

  condition:
    any of them
}