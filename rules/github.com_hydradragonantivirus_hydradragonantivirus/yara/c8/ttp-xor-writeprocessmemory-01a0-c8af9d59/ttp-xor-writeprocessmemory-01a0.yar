rule TTP_XOR_WriteProcessMemory_01a0 {
  strings:
    $key_01a0 = { 56 d2 [2] 64 f0 [2] 62 c5 [2] 4c c5 [2] 73 d9 }

  condition:
    any of them
}