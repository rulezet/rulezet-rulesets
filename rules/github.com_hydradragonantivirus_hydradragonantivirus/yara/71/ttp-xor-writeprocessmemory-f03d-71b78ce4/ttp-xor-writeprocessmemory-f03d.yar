rule TTP_XOR_WriteProcessMemory_f03d {
  strings:
    $key_f03d = { a7 4f [2] 95 6d [2] 93 58 [2] bd 58 [2] 82 44 }

  condition:
    any of them
}