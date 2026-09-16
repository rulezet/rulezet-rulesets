rule TTP_XOR_WriteProcessMemory_64b1 {
  strings:
    $key_64b1 = { 33 c3 [2] 01 e1 [2] 07 d4 [2] 29 d4 [2] 16 c8 }

  condition:
    any of them
}