rule TTP_XOR_WriteProcessMemory_8ca9 {
  strings:
    $key_8ca9 = { db db [2] e9 f9 [2] ef cc [2] c1 cc [2] fe d0 }

  condition:
    any of them
}