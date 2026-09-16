rule TTP_XOR_WriteProcessMemory_d821 {
  strings:
    $key_d821 = { 8f 53 [2] bd 71 [2] bb 44 [2] 95 44 [2] aa 58 }

  condition:
    any of them
}