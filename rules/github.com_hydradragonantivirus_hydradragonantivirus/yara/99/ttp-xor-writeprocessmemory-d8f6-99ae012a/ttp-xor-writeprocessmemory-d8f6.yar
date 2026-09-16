rule TTP_XOR_WriteProcessMemory_d8f6 {
  strings:
    $key_d8f6 = { 8f 84 [2] bd a6 [2] bb 93 [2] 95 93 [2] aa 8f }

  condition:
    any of them
}