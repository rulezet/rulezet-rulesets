rule TTP_XOR_WriteProcessMemory_f011 {
  strings:
    $key_f011 = { a7 63 [2] 95 41 [2] 93 74 [2] bd 74 [2] 82 68 }

  condition:
    any of them
}