rule TTP_XOR_WriteProcessMemory_f016 {
  strings:
    $key_f016 = { a7 64 [2] 95 46 [2] 93 73 [2] bd 73 [2] 82 6f }

  condition:
    any of them
}