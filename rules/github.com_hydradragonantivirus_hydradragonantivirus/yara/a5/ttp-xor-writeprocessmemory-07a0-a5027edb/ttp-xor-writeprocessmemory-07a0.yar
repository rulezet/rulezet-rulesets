rule TTP_XOR_WriteProcessMemory_07a0 {
  strings:
    $key_07a0 = { 50 d2 [2] 62 f0 [2] 64 c5 [2] 4a c5 [2] 75 d9 }

  condition:
    any of them
}