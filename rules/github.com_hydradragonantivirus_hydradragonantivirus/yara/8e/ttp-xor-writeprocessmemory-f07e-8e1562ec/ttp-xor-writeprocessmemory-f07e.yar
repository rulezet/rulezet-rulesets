rule TTP_XOR_WriteProcessMemory_f07e {
  strings:
    $key_f07e = { a7 0c [2] 95 2e [2] 93 1b [2] bd 1b [2] 82 07 }

  condition:
    any of them
}