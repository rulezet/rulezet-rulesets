rule TTP_XOR_WriteProcessMemory_69a1 {
  strings:
    $key_69a1 = { 3e d3 [2] 0c f1 [2] 0a c4 [2] 24 c4 [2] 1b d8 }

  condition:
    any of them
}