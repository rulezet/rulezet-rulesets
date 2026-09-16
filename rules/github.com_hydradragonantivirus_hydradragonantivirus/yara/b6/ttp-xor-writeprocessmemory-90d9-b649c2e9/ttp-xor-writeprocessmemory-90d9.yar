rule TTP_XOR_WriteProcessMemory_90d9 {
  strings:
    $key_90d9 = { c7 ab [2] f5 89 [2] f3 bc [2] dd bc [2] e2 a0 }

  condition:
    any of them
}