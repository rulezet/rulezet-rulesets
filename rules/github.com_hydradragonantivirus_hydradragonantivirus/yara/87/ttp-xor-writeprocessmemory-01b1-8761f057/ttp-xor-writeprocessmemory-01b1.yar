rule TTP_XOR_WriteProcessMemory_01b1 {
  strings:
    $key_01b1 = { 56 c3 [2] 64 e1 [2] 62 d4 [2] 4c d4 [2] 73 c8 }

  condition:
    any of them
}