rule TTP_XOR_WriteProcessMemory_69a0 {
  strings:
    $key_69a0 = { 3e d2 [2] 0c f0 [2] 0a c5 [2] 24 c5 [2] 1b d9 }

  condition:
    any of them
}