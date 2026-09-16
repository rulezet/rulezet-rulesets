rule TTP_XOR_WriteProcessMemory_f048 {
  strings:
    $key_f048 = { a7 3a [2] 95 18 [2] 93 2d [2] bd 2d [2] 82 31 }

  condition:
    any of them
}