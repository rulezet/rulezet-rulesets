rule TTP_XOR_WriteProcessMemory_f020 {
  strings:
    $key_f020 = { a7 52 [2] 95 70 [2] 93 45 [2] bd 45 [2] 82 59 }

  condition:
    any of them
}