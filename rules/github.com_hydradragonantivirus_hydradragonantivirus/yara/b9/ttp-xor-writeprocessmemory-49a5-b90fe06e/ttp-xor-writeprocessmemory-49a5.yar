rule TTP_XOR_WriteProcessMemory_49a5 {
  strings:
    $key_49a5 = { 1e d7 [2] 2c f5 [2] 2a c0 [2] 04 c0 [2] 3b dc }

  condition:
    any of them
}