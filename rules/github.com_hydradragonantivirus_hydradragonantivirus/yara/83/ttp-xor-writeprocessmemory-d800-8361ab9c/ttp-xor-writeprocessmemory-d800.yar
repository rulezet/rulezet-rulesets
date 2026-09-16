rule TTP_XOR_WriteProcessMemory_d800 {
  strings:
    $key_d800 = { 8f 72 [2] bd 50 [2] bb 65 [2] 95 65 [2] aa 79 }

  condition:
    any of them
}