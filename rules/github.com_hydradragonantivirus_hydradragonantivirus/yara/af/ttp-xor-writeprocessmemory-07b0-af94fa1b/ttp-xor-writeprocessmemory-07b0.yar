rule TTP_XOR_WriteProcessMemory_07b0 {
  strings:
    $key_07b0 = { 50 c2 [2] 62 e0 [2] 64 d5 [2] 4a d5 [2] 75 c9 }

  condition:
    any of them
}