rule TTP_XOR_WriteProcessMemory_69a6 {
  strings:
    $key_69a6 = { 3e d4 [2] 0c f6 [2] 0a c3 [2] 24 c3 [2] 1b df }

  condition:
    any of them
}