rule TTP_XOR_WriteProcessMemory_2e80 {
  strings:
    $key_2e80 = { 79 f2 [2] 4b d0 [2] 4d e5 [2] 63 e5 [2] 5c f9 }

  condition:
    any of them
}