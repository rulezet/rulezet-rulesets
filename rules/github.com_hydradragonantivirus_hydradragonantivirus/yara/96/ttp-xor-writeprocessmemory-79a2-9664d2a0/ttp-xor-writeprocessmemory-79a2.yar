rule TTP_XOR_WriteProcessMemory_79a2 {
  strings:
    $key_79a2 = { 2e d0 [2] 1c f2 [2] 1a c7 [2] 34 c7 [2] 0b db }

  condition:
    any of them
}