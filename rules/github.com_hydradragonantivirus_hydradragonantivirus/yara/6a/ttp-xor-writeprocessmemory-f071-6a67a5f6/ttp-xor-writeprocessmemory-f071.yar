rule TTP_XOR_WriteProcessMemory_f071 {
  strings:
    $key_f071 = { a7 03 [2] 95 21 [2] 93 14 [2] bd 14 [2] 82 08 }

  condition:
    any of them
}