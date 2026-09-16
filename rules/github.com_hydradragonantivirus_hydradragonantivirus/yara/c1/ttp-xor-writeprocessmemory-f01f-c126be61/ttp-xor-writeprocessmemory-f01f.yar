rule TTP_XOR_WriteProcessMemory_f01f {
  strings:
    $key_f01f = { a7 6d [2] 95 4f [2] 93 7a [2] bd 7a [2] 82 66 }

  condition:
    any of them
}