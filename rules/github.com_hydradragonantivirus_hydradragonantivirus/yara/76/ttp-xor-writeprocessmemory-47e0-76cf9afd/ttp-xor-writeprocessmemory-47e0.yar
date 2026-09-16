rule TTP_XOR_WriteProcessMemory_47e0 {
  strings:
    $key_47e0 = { 10 92 [2] 22 b0 [2] 24 85 [2] 0a 85 [2] 35 99 }

  condition:
    any of them
}