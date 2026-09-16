rule TTP_XOR_WriteProcessMemory_7ca1 {
  strings:
    $key_7ca1 = { 2b d3 [2] 19 f1 [2] 1f c4 [2] 31 c4 [2] 0e d8 }

  condition:
    any of them
}