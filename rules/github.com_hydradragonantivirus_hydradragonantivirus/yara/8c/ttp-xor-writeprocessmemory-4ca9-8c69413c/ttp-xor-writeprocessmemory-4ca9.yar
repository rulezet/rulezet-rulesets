rule TTP_XOR_WriteProcessMemory_4ca9 {
  strings:
    $key_4ca9 = { 1b db [2] 29 f9 [2] 2f cc [2] 01 cc [2] 3e d0 }

  condition:
    any of them
}