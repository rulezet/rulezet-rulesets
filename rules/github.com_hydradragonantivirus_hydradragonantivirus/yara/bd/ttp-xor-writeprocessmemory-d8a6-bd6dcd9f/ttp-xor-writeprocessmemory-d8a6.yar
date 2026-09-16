rule TTP_XOR_WriteProcessMemory_d8a6 {
  strings:
    $key_d8a6 = { 8f d4 [2] bd f6 [2] bb c3 [2] 95 c3 [2] aa df }

  condition:
    any of them
}