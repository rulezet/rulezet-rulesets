rule TTP_XOR_WriteProcessMemory_f0e3 {
  strings:
    $key_f0e3 = { a7 91 [2] 95 b3 [2] 93 86 [2] bd 86 [2] 82 9a }

  condition:
    any of them
}