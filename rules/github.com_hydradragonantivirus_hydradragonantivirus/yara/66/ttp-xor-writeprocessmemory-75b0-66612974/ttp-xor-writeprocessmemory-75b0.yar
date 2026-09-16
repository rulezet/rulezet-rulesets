rule TTP_XOR_WriteProcessMemory_75b0 {
  strings:
    $key_75b0 = { 22 c2 [2] 10 e0 [2] 16 d5 [2] 38 d5 [2] 07 c9 }

  condition:
    any of them
}