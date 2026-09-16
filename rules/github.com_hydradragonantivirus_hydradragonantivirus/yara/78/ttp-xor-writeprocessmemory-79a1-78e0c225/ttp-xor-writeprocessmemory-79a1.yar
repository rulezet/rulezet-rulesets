rule TTP_XOR_WriteProcessMemory_79a1 {
  strings:
    $key_79a1 = { 2e d3 [2] 1c f1 [2] 1a c4 [2] 34 c4 [2] 0b d8 }

  condition:
    any of them
}