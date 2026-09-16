rule TTP_XOR_WriteProcessMemory_4ca1 {
  strings:
    $key_4ca1 = { 1b d3 [2] 29 f1 [2] 2f c4 [2] 01 c4 [2] 3e d8 }

  condition:
    any of them
}