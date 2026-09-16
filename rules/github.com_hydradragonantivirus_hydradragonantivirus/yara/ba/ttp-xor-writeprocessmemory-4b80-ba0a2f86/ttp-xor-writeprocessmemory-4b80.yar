rule TTP_XOR_WriteProcessMemory_4b80 {
  strings:
    $key_4b80 = { 1c f2 [2] 2e d0 [2] 28 e5 [2] 06 e5 [2] 39 f9 }

  condition:
    any of them
}