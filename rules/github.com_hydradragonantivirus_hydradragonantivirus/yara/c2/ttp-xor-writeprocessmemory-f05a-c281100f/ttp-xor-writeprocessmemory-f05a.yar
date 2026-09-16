rule TTP_XOR_WriteProcessMemory_f05a {
  strings:
    $key_f05a = { a7 28 [2] 95 0a [2] 93 3f [2] bd 3f [2] 82 23 }

  condition:
    any of them
}