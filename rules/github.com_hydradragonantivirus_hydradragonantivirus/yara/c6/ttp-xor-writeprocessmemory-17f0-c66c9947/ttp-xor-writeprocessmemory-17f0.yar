rule TTP_XOR_WriteProcessMemory_17f0 {
  strings:
    $key_17f0 = { 40 82 [2] 72 a0 [2] 74 95 [2] 5a 95 [2] 65 89 }

  condition:
    any of them
}