rule TTP_XOR_WriteProcessMemory_d8a3 {
  strings:
    $key_d8a3 = { 8f d1 [2] bd f3 [2] bb c6 [2] 95 c6 [2] aa da }

  condition:
    any of them
}