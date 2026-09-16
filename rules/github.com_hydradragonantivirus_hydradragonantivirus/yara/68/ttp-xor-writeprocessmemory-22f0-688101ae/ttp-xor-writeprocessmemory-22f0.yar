rule TTP_XOR_WriteProcessMemory_22f0 {
  strings:
    $key_22f0 = { 75 82 [2] 47 a0 [2] 41 95 [2] 6f 95 [2] 50 89 }

  condition:
    any of them
}