rule TTP_XOR_WriteProcessMemory_f0f5 {
  strings:
    $key_f0f5 = { a7 87 [2] 95 a5 [2] 93 90 [2] bd 90 [2] 82 8c }

  condition:
    any of them
}