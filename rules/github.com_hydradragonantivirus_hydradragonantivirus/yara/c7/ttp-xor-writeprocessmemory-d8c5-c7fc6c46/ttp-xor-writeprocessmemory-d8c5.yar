rule TTP_XOR_WriteProcessMemory_d8c5 {
  strings:
    $key_d8c5 = { 8f b7 [2] bd 95 [2] bb a0 [2] 95 a0 [2] aa bc }

  condition:
    any of them
}