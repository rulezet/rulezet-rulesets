rule TTP_XOR_WriteProcessMemory_f074 {
  strings:
    $key_f074 = { a7 06 [2] 95 24 [2] 93 11 [2] bd 11 [2] 82 0d }

  condition:
    any of them
}