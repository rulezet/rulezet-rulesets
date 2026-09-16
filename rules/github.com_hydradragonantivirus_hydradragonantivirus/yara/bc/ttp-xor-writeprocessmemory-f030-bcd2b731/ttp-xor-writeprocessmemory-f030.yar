rule TTP_XOR_WriteProcessMemory_f030 {
  strings:
    $key_f030 = { a7 42 [2] 95 60 [2] 93 55 [2] bd 55 [2] 82 49 }

  condition:
    any of them
}