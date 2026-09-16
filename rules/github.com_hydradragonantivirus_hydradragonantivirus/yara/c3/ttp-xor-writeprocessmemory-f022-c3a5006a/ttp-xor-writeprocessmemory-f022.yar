rule TTP_XOR_WriteProcessMemory_f022 {
  strings:
    $key_f022 = { a7 50 [2] 95 72 [2] 93 47 [2] bd 47 [2] 82 5b }

  condition:
    any of them
}