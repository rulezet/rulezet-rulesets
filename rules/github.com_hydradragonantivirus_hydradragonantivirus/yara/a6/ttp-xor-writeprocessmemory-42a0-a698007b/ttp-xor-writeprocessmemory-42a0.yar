rule TTP_XOR_WriteProcessMemory_42a0 {
  strings:
    $key_42a0 = { 15 d2 [2] 27 f0 [2] 21 c5 [2] 0f c5 [2] 30 d9 }

  condition:
    any of them
}