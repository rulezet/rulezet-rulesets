rule TTP_XOR_WriteProcessMemory_f05d {
  strings:
    $key_f05d = { a7 2f [2] 95 0d [2] 93 38 [2] bd 38 [2] 82 24 }

  condition:
    any of them
}