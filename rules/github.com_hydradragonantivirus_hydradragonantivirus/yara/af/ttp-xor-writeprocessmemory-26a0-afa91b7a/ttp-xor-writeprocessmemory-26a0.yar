rule TTP_XOR_WriteProcessMemory_26a0 {
  strings:
    $key_26a0 = { 71 d2 [2] 43 f0 [2] 45 c5 [2] 6b c5 [2] 54 d9 }

  condition:
    any of them
}