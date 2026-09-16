rule TTP_XOR_WriteProcessMemory_19a5 {
  strings:
    $key_19a5 = { 4e d7 [2] 7c f5 [2] 7a c0 [2] 54 c0 [2] 6b dc }

  condition:
    any of them
}