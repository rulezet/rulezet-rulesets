rule TTP_XOR_WriteProcessMemory_f007 {
  strings:
    $key_f007 = { a7 75 [2] 95 57 [2] 93 62 [2] bd 62 [2] 82 7e }

  condition:
    any of them
}