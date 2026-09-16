rule TTP_XOR_WriteProcessMemory_29a4 {
  strings:
    $key_29a4 = { 7e d6 [2] 4c f4 [2] 4a c1 [2] 64 c1 [2] 5b dd }

  condition:
    any of them
}