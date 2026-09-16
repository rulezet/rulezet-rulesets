rule TTP_XOR_WriteProcessMemory_d830 {
  strings:
    $key_d830 = { 8f 42 [2] bd 60 [2] bb 55 [2] 95 55 [2] aa 49 }

  condition:
    any of them
}