rule TTP_XOR_WriteProcessMemory_90d6 {
  strings:
    $key_90d6 = { c7 a4 [2] f5 86 [2] f3 b3 [2] dd b3 [2] e2 af }

  condition:
    any of them
}