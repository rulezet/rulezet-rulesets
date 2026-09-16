rule TTP_XOR_WriteProcessMemory_90d4 {
  strings:
    $key_90d4 = { c7 a6 [2] f5 84 [2] f3 b1 [2] dd b1 [2] e2 ad }

  condition:
    any of them
}