rule TTP_XOR_WriteProcessMemory_64b0 {
  strings:
    $key_64b0 = { 33 c2 [2] 01 e0 [2] 07 d5 [2] 29 d5 [2] 16 c9 }

  condition:
    any of them
}