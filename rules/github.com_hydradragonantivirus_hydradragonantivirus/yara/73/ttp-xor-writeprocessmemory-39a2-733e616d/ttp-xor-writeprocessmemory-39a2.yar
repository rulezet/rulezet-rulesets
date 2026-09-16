rule TTP_XOR_WriteProcessMemory_39a2 {
  strings:
    $key_39a2 = { 6e d0 [2] 5c f2 [2] 5a c7 [2] 74 c7 [2] 4b db }

  condition:
    any of them
}