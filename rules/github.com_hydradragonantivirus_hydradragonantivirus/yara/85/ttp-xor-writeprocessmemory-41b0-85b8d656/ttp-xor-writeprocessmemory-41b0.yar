rule TTP_XOR_WriteProcessMemory_41b0 {
  strings:
    $key_41b0 = { 16 c2 [2] 24 e0 [2] 22 d5 [2] 0c d5 [2] 33 c9 }

  condition:
    any of them
}