rule TTP_XOR_WriteProcessMemory_f04c {
  strings:
    $key_f04c = { a7 3e [2] 95 1c [2] 93 29 [2] bd 29 [2] 82 35 }

  condition:
    any of them
}