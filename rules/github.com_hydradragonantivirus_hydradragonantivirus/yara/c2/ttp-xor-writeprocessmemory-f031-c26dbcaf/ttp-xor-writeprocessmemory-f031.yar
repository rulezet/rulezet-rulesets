rule TTP_XOR_WriteProcessMemory_f031 {
  strings:
    $key_f031 = { a7 43 [2] 95 61 [2] 93 54 [2] bd 54 [2] 82 48 }

  condition:
    any of them
}