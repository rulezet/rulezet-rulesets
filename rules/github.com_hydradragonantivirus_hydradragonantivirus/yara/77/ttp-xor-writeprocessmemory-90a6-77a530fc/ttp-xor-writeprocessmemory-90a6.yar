rule TTP_XOR_WriteProcessMemory_90a6 {
  strings:
    $key_90a6 = { c7 d4 [2] f5 f6 [2] f3 c3 [2] dd c3 [2] e2 df }

  condition:
    any of them
}