rule TTP_XOR_WriteProcessMemory_13f0 {
  strings:
    $key_13f0 = { 44 82 [2] 76 a0 [2] 70 95 [2] 5e 95 [2] 61 89 }

  condition:
    any of them
}