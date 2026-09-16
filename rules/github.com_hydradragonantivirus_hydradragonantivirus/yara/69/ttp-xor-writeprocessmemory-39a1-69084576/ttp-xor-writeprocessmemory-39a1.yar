rule TTP_XOR_WriteProcessMemory_39a1 {
  strings:
    $key_39a1 = { 6e d3 [2] 5c f1 [2] 5a c4 [2] 74 c4 [2] 4b d8 }

  condition:
    any of them
}