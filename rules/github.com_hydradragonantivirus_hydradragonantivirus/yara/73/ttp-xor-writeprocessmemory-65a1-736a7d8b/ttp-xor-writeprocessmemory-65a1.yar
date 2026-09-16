rule TTP_XOR_WriteProcessMemory_65a1 {
  strings:
    $key_65a1 = { 32 d3 [2] 00 f1 [2] 06 c4 [2] 28 c4 [2] 17 d8 }

  condition:
    any of them
}