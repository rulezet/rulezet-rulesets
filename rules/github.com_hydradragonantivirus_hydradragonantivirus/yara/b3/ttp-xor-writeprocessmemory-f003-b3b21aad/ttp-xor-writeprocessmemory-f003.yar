rule TTP_XOR_WriteProcessMemory_f003 {
  strings:
    $key_f003 = { a7 71 [2] 95 53 [2] 93 66 [2] bd 66 [2] 82 7a }

  condition:
    any of them
}