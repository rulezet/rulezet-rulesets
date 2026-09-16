rule TTP_XOR_WriteProcessMemory_11a0 {
  strings:
    $key_11a0 = { 46 d2 [2] 74 f0 [2] 72 c5 [2] 5c c5 [2] 63 d9 }

  condition:
    any of them
}