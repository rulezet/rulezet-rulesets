rule TTP_XOR_WriteProcessMemory_f00b {
  strings:
    $key_f00b = { a7 79 [2] 95 5b [2] 93 6e [2] bd 6e [2] 82 72 }

  condition:
    any of them
}