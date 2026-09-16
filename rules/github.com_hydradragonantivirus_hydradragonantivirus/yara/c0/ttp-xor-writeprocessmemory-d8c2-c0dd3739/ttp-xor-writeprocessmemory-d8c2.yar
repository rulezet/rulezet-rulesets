rule TTP_XOR_WriteProcessMemory_d8c2 {
  strings:
    $key_d8c2 = { 8f b0 [2] bd 92 [2] bb a7 [2] 95 a7 [2] aa bb }

  condition:
    any of them
}