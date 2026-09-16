rule TTP_XOR_WriteProcessMemory_09a4 {
  strings:
    $key_09a4 = { 5e d6 [2] 6c f4 [2] 6a c1 [2] 44 c1 [2] 7b dd }

  condition:
    any of them
}