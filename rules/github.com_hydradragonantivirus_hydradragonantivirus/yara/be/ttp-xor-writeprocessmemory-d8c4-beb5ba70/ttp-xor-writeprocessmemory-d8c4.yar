rule TTP_XOR_WriteProcessMemory_d8c4 {
  strings:
    $key_d8c4 = { 8f b6 [2] bd 94 [2] bb a1 [2] 95 a1 [2] aa bd }

  condition:
    any of them
}