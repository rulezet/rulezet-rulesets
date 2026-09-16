rule TTP_XOR_WriteProcessMemory_f05b {
  strings:
    $key_f05b = { a7 29 [2] 95 0b [2] 93 3e [2] bd 3e [2] 82 22 }

  condition:
    any of them
}