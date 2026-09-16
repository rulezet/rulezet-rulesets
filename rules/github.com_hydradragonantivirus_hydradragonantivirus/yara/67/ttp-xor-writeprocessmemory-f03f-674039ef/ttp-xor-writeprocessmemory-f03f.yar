rule TTP_XOR_WriteProcessMemory_f03f {
  strings:
    $key_f03f = { a7 4d [2] 95 6f [2] 93 5a [2] bd 5a [2] 82 46 }

  condition:
    any of them
}