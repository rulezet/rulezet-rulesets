rule TTP_XOR_WriteProcessMemory_f026 {
  strings:
    $key_f026 = { a7 54 [2] 95 76 [2] 93 43 [2] bd 43 [2] 82 5f }

  condition:
    any of them
}