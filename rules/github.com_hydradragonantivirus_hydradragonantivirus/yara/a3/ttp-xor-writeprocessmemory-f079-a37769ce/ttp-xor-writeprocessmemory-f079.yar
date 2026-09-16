rule TTP_XOR_WriteProcessMemory_f079 {
  strings:
    $key_f079 = { a7 0b [2] 95 29 [2] 93 1c [2] bd 1c [2] 82 00 }

  condition:
    any of them
}