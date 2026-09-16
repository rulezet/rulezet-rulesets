rule TTP_XOR_WriteProcessMemory_0ca9 {
  strings:
    $key_0ca9 = { 5b db [2] 69 f9 [2] 6f cc [2] 41 cc [2] 7e d0 }

  condition:
    any of them
}