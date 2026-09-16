rule TTP_XOR_WriteProcessMemory_5ca9 {
  strings:
    $key_5ca9 = { 0b db [2] 39 f9 [2] 3f cc [2] 11 cc [2] 2e d0 }

  condition:
    any of them
}