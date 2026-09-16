rule TTP_XOR_WriteProcessMemory_47a1 {
  strings:
    $key_47a1 = { 10 d3 [2] 22 f1 [2] 24 c4 [2] 0a c4 [2] 35 d8 }

  condition:
    any of them
}