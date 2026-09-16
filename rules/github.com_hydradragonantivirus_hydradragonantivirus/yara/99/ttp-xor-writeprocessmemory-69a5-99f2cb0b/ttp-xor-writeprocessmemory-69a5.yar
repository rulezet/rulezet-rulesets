rule TTP_XOR_WriteProcessMemory_69a5 {
  strings:
    $key_69a5 = { 3e d7 [2] 0c f5 [2] 0a c0 [2] 24 c0 [2] 1b dc }

  condition:
    any of them
}