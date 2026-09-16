rule TTP_XOR_WriteProcessMemory_77a1 {
  strings:
    $key_77a1 = { 20 d3 [2] 12 f1 [2] 14 c4 [2] 3a c4 [2] 05 d8 }

  condition:
    any of them
}