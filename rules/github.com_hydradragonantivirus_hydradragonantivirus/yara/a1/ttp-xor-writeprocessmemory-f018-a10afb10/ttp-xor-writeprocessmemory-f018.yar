rule TTP_XOR_WriteProcessMemory_f018 {
  strings:
    $key_f018 = { a7 6a [2] 95 48 [2] 93 7d [2] bd 7d [2] 82 61 }

  condition:
    any of them
}