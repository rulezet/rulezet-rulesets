rule TTP_XOR_WriteProcessMemory_f06c {
  strings:
    $key_f06c = { a7 1e [2] 95 3c [2] 93 09 [2] bd 09 [2] 82 15 }

  condition:
    any of them
}