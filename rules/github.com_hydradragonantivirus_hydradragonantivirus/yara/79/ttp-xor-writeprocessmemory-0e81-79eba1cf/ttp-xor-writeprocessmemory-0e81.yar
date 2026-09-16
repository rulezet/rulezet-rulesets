rule TTP_XOR_WriteProcessMemory_0e81 {
  strings:
    $key_0e81 = { 59 f3 [2] 6b d1 [2] 6d e4 [2] 43 e4 [2] 7c f8 }

  condition:
    any of them
}