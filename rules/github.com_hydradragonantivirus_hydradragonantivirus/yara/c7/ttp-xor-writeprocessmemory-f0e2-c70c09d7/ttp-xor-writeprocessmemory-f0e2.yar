rule TTP_XOR_WriteProcessMemory_f0e2 {
  strings:
    $key_f0e2 = { a7 90 [2] 95 b2 [2] 93 87 [2] bd 87 [2] 82 9b }

  condition:
    any of them
}