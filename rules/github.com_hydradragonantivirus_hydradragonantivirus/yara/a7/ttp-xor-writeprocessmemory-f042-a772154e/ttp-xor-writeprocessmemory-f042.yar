rule TTP_XOR_WriteProcessMemory_f042 {
  strings:
    $key_f042 = { a7 30 [2] 95 12 [2] 93 27 [2] bd 27 [2] 82 3b }

  condition:
    any of them
}