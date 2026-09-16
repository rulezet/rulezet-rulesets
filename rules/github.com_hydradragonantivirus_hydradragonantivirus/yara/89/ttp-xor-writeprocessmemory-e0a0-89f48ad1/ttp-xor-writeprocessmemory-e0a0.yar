rule TTP_XOR_WriteProcessMemory_e0a0 {
  strings:
    $key_e0a0 = { b7 d2 [2] 85 f0 [2] 83 c5 [2] ad c5 [2] 92 d9 }

  condition:
    any of them
}