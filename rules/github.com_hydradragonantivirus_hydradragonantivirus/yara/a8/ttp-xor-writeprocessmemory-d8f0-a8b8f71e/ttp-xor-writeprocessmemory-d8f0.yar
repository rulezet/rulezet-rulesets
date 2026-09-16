rule TTP_XOR_WriteProcessMemory_d8f0 {
  strings:
    $key_d8f0 = { 8f 82 [2] bd a0 [2] bb 95 [2] 95 95 [2] aa 89 }

  condition:
    any of them
}