rule TTP_XOR_WriteProcessMemory_f060 {
  strings:
    $key_f060 = { a7 12 [2] 95 30 [2] 93 05 [2] bd 05 [2] 82 19 }

  condition:
    any of them
}