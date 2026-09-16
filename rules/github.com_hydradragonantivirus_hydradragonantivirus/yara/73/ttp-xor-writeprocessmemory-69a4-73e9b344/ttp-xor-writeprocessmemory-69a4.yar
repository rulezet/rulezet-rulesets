rule TTP_XOR_WriteProcessMemory_69a4 {
  strings:
    $key_69a4 = { 3e d6 [2] 0c f4 [2] 0a c1 [2] 24 c1 [2] 1b dd }

  condition:
    any of them
}