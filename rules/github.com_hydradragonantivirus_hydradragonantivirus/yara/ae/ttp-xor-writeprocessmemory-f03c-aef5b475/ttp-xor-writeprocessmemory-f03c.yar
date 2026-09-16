rule TTP_XOR_WriteProcessMemory_f03c {
  strings:
    $key_f03c = { a7 4e [2] 95 6c [2] 93 59 [2] bd 59 [2] 82 45 }

  condition:
    any of them
}