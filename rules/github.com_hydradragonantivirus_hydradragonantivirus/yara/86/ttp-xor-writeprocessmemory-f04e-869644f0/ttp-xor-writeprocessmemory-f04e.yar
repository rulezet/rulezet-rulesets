rule TTP_XOR_WriteProcessMemory_f04e {
  strings:
    $key_f04e = { a7 3c [2] 95 1e [2] 93 2b [2] bd 2b [2] 82 37 }

  condition:
    any of them
}