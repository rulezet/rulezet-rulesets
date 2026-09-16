rule TTP_XOR_WriteProcessMemory_f038 {
  strings:
    $key_f038 = { a7 4a [2] 95 68 [2] 93 5d [2] bd 5d [2] 82 41 }

  condition:
    any of them
}