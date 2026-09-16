rule TTP_XOR_WriteProcessMemory_f066 {
  strings:
    $key_f066 = { a7 14 [2] 95 36 [2] 93 03 [2] bd 03 [2] 82 1f }

  condition:
    any of them
}