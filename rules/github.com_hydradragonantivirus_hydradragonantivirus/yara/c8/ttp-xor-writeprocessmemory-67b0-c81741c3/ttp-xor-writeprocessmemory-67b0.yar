rule TTP_XOR_WriteProcessMemory_67b0 {
  strings:
    $key_67b0 = { 30 c2 [2] 02 e0 [2] 04 d5 [2] 2a d5 [2] 15 c9 }

  condition:
    any of them
}