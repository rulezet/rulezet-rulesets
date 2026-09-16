rule TTP_XOR_WriteProcessMemory_3ca1 {
  strings:
    $key_3ca1 = { 6b d3 [2] 59 f1 [2] 5f c4 [2] 71 c4 [2] 4e d8 }

  condition:
    any of them
}