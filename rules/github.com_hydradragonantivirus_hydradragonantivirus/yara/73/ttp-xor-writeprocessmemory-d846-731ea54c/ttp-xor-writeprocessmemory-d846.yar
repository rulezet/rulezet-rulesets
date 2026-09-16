rule TTP_XOR_WriteProcessMemory_d846 {
  strings:
    $key_d846 = { 8f 34 [2] bd 16 [2] bb 23 [2] 95 23 [2] aa 3f }

  condition:
    any of them
}