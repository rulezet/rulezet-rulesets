rule TTP_XOR_WriteProcessMemory_12a0 {
  strings:
    $key_12a0 = { 45 d2 [2] 77 f0 [2] 71 c5 [2] 5f c5 [2] 60 d9 }

  condition:
    any of them
}