rule TTP_XOR_WriteProcessMemory_41a0 {
  strings:
    $key_41a0 = { 16 d2 [2] 24 f0 [2] 22 c5 [2] 0c c5 [2] 33 d9 }

  condition:
    any of them
}