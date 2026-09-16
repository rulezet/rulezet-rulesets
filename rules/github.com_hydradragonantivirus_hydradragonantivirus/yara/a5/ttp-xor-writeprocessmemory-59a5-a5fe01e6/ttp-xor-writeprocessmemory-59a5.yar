rule TTP_XOR_WriteProcessMemory_59a5 {
  strings:
    $key_59a5 = { 0e d7 [2] 3c f5 [2] 3a c0 [2] 14 c0 [2] 2b dc }

  condition:
    any of them
}