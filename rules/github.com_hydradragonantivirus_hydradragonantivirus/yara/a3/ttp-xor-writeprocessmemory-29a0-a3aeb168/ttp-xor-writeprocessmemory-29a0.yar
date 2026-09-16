rule TTP_XOR_WriteProcessMemory_29a0 {
  strings:
    $key_29a0 = { 7e d2 [2] 4c f0 [2] 4a c5 [2] 64 c5 [2] 5b d9 }

  condition:
    any of them
}