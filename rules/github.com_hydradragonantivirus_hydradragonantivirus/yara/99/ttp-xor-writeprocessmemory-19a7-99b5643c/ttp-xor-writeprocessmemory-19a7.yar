rule TTP_XOR_WriteProcessMemory_19a7 {
  strings:
    $key_19a7 = { 4e d5 [2] 7c f7 [2] 7a c2 [2] 54 c2 [2] 6b de }

  condition:
    any of them
}