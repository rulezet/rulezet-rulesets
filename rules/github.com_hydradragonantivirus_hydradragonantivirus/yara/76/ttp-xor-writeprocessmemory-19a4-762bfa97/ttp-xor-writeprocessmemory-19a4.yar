rule TTP_XOR_WriteProcessMemory_19a4 {
  strings:
    $key_19a4 = { 4e d6 [2] 7c f4 [2] 7a c1 [2] 54 c1 [2] 6b dd }

  condition:
    any of them
}