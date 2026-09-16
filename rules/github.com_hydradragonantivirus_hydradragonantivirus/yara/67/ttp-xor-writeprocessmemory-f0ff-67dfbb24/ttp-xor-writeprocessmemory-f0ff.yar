rule TTP_XOR_WriteProcessMemory_f0ff {
  strings:
    $key_f0ff = { a7 8d [2] 95 af [2] 93 9a [2] bd 9a [2] 82 86 }

  condition:
    any of them
}