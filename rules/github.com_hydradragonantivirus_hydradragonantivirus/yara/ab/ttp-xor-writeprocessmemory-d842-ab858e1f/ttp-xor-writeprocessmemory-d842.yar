rule TTP_XOR_WriteProcessMemory_d842 {
  strings:
    $key_d842 = { 8f 30 [2] bd 12 [2] bb 27 [2] 95 27 [2] aa 3b }

  condition:
    any of them
}