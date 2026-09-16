rule TTP_XOR_WriteProcessMemory_f0f0 {
  strings:
    $key_f0f0 = { a7 82 [2] 95 a0 [2] 93 95 [2] bd 95 [2] 82 89 }

  condition:
    any of them
}