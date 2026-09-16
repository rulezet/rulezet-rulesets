rule TTP_XOR_WriteProcessMemory_25f0 {
  strings:
    $key_25f0 = { 72 82 [2] 40 a0 [2] 46 95 [2] 68 95 [2] 57 89 }

  condition:
    any of them
}