rule TTP_XOR_WriteProcessMemory_d806 {
  strings:
    $key_d806 = { 8f 74 [2] bd 56 [2] bb 63 [2] 95 63 [2] aa 7f }

  condition:
    any of them
}