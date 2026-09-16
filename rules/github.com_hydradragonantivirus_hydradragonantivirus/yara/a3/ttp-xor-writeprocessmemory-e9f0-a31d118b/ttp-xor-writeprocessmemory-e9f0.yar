rule TTP_XOR_WriteProcessMemory_e9f0 {
  strings:
    $key_e9f0 = { be 82 [2] 8c a0 [2] 8a 95 [2] a4 95 [2] 9b 89 }

  condition:
    any of them
}