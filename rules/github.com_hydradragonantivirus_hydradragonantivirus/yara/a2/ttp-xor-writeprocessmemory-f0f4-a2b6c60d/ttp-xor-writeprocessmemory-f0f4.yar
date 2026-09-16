rule TTP_XOR_WriteProcessMemory_f0f4 {
  strings:
    $key_f0f4 = { a7 86 [2] 95 a4 [2] 93 91 [2] bd 91 [2] 82 8d }

  condition:
    any of them
}