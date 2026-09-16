rule TTP_XOR_WriteProcessMemory_6b80 {
  strings:
    $key_6b80 = { 3c f2 [2] 0e d0 [2] 08 e5 [2] 26 e5 [2] 19 f9 }

  condition:
    any of them
}