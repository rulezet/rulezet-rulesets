rule TTP_XOR_WriteProcessMemory_ece0 {
  strings:
    $key_ece0 = { bb 92 [2] 89 b0 [2] 8f 85 [2] a1 85 [2] 9e 99 }

  condition:
    any of them
}