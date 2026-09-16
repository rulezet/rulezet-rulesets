rule TTP_XOR_WriteProcessMemory_16f0 {
  strings:
    $key_16f0 = { 41 82 [2] 73 a0 [2] 75 95 [2] 5b 95 [2] 64 89 }

  condition:
    any of them
}