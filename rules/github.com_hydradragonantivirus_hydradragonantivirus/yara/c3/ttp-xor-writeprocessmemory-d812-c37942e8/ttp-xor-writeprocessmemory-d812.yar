rule TTP_XOR_WriteProcessMemory_d812 {
  strings:
    $key_d812 = { 8f 60 [2] bd 42 [2] bb 77 [2] 95 77 [2] aa 6b }

  condition:
    any of them
}