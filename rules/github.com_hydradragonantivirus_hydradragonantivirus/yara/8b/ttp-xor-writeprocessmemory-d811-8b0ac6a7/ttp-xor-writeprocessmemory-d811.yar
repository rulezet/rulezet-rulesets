rule TTP_XOR_WriteProcessMemory_d811 {
  strings:
    $key_d811 = { 8f 63 [2] bd 41 [2] bb 74 [2] 95 74 [2] aa 68 }

  condition:
    any of them
}