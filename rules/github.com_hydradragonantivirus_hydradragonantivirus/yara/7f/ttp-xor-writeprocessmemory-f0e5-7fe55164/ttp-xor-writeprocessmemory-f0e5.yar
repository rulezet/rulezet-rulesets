rule TTP_XOR_WriteProcessMemory_f0e5 {
  strings:
    $key_f0e5 = { a7 97 [2] 95 b5 [2] 93 80 [2] bd 80 [2] 82 9c }

  condition:
    any of them
}