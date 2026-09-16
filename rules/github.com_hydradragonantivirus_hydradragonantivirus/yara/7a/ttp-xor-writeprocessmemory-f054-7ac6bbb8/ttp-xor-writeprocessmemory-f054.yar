rule TTP_XOR_WriteProcessMemory_f054 {
  strings:
    $key_f054 = { a7 26 [2] 95 04 [2] 93 31 [2] bd 31 [2] 82 2d }

  condition:
    any of them
}