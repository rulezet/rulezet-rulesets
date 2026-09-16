rule TTP_XOR_WriteProcessMemory_7e81 {
  strings:
    $key_7e81 = { 29 f3 [2] 1b d1 [2] 1d e4 [2] 33 e4 [2] 0c f8 }

  condition:
    any of them
}