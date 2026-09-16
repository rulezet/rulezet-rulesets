rule TTP_XOR_WriteProcessMemory_f0f2 {
  strings:
    $key_f0f2 = { a7 80 [2] 95 a2 [2] 93 97 [2] bd 97 [2] 82 8b }

  condition:
    any of them
}