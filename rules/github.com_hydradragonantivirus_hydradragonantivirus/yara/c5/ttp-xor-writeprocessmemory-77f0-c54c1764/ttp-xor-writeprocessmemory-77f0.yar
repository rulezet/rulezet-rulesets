rule TTP_XOR_WriteProcessMemory_77f0 {
  strings:
    $key_77f0 = { 20 82 [2] 12 a0 [2] 14 95 [2] 3a 95 [2] 05 89 }

  condition:
    any of them
}