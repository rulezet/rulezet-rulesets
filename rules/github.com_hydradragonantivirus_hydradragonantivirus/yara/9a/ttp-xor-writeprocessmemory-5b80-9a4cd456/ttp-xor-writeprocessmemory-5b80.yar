rule TTP_XOR_WriteProcessMemory_5b80 {
  strings:
    $key_5b80 = { 0c f2 [2] 3e d0 [2] 38 e5 [2] 16 e5 [2] 29 f9 }

  condition:
    any of them
}