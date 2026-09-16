rule TTP_XOR_WriteProcessMemory_56b1 {
  strings:
    $key_56b1 = { 01 c3 [2] 33 e1 [2] 35 d4 [2] 1b d4 [2] 24 c8 }

  condition:
    any of them
}