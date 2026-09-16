rule TTP_XOR_WriteProcessMemory_7da0 {
  strings:
    $key_7da0 = { 2a d2 [2] 18 f0 [2] 1e c5 [2] 30 c5 [2] 0f d9 }

  condition:
    any of them
}