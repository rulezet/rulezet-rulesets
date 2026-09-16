rule TTP_XOR_WriteProcessMemory_d856 {
  strings:
    $key_d856 = { 8f 24 [2] bd 06 [2] bb 33 [2] 95 33 [2] aa 2f }

  condition:
    any of them
}