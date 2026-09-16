rule TTP_XOR_WriteProcessMemory_f05c {
  strings:
    $key_f05c = { a7 2e [2] 95 0c [2] 93 39 [2] bd 39 [2] 82 25 }

  condition:
    any of them
}