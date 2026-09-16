rule TTP_XOR_WriteProcessMemory_5da0 {
  strings:
    $key_5da0 = { 0a d2 [2] 38 f0 [2] 3e c5 [2] 10 c5 [2] 2f d9 }

  condition:
    any of them
}