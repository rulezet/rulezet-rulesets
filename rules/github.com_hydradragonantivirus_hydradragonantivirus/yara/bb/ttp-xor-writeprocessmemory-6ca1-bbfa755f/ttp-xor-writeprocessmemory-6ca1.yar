rule TTP_XOR_WriteProcessMemory_6ca1 {
  strings:
    $key_6ca1 = { 3b d3 [2] 09 f1 [2] 0f c4 [2] 21 c4 [2] 1e d8 }

  condition:
    any of them
}