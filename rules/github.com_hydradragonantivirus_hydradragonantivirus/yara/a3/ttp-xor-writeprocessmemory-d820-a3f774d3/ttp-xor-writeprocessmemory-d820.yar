rule TTP_XOR_WriteProcessMemory_d820 {
  strings:
    $key_d820 = { 8f 52 [2] bd 70 [2] bb 45 [2] 95 45 [2] aa 59 }

  condition:
    any of them
}