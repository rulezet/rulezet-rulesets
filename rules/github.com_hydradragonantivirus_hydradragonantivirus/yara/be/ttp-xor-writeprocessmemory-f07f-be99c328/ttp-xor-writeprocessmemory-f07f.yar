rule TTP_XOR_WriteProcessMemory_f07f {
  strings:
    $key_f07f = { a7 0d [2] 95 2f [2] 93 1a [2] bd 1a [2] 82 06 }

  condition:
    any of them
}