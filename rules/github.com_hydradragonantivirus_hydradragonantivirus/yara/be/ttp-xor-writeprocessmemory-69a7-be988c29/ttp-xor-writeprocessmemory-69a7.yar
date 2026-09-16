rule TTP_XOR_WriteProcessMemory_69a7 {
  strings:
    $key_69a7 = { 3e d5 [2] 0c f7 [2] 0a c2 [2] 24 c2 [2] 1b de }

  condition:
    any of them
}