rule TTP_XOR_WriteProcessMemory_0ed9 {
  strings:
    $key_0ed9 = { 59 ab [2] 6b 89 [2] 6d bc [2] 43 bc [2] 7c a0 }

  condition:
    any of them
}