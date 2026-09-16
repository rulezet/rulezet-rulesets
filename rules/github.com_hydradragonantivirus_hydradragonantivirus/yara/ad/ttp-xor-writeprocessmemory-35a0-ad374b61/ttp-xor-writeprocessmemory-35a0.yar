rule TTP_XOR_WriteProcessMemory_35a0 {
  strings:
    $key_35a0 = { 62 d2 [2] 50 f0 [2] 56 c5 [2] 78 c5 [2] 47 d9 }

  condition:
    any of them
}