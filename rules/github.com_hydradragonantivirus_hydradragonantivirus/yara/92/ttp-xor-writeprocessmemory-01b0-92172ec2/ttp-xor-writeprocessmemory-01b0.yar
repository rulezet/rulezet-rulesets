rule TTP_XOR_WriteProcessMemory_01b0 {
  strings:
    $key_01b0 = { 56 c2 [2] 64 e0 [2] 62 d5 [2] 4c d5 [2] 73 c9 }

  condition:
    any of them
}