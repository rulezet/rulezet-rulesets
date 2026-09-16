rule TTP_XOR_WriteProcessMemory_09a1 {
  strings:
    $key_09a1 = { 5e d3 [2] 6c f1 [2] 6a c4 [2] 44 c4 [2] 7b d8 }

  condition:
    any of them
}