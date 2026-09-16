rule TTP_XOR_WriteProcessMemory_d843 {
  strings:
    $key_d843 = { 8f 31 [2] bd 13 [2] bb 26 [2] 95 26 [2] aa 3a }

  condition:
    any of them
}