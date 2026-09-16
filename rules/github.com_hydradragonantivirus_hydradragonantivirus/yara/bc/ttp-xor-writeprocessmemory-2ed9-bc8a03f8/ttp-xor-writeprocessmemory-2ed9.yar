rule TTP_XOR_WriteProcessMemory_2ed9 {
  strings:
    $key_2ed9 = { 79 ab [2] 4b 89 [2] 4d bc [2] 63 bc [2] 5c a0 }

  condition:
    any of them
}