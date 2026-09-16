rule TTP_XOR_WriteProcessMemory_09a2 {
  strings:
    $key_09a2 = { 5e d0 [2] 6c f2 [2] 6a c7 [2] 44 c7 [2] 7b db }

  condition:
    any of them
}