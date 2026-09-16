rule TTP_XOR_WriteProcessMemory_07b1 {
  strings:
    $key_07b1 = { 50 c3 [2] 62 e1 [2] 64 d4 [2] 4a d4 [2] 75 c8 }

  condition:
    any of them
}