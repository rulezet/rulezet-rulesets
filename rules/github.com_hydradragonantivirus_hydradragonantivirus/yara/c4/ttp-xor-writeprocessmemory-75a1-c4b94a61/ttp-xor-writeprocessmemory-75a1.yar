rule TTP_XOR_WriteProcessMemory_75a1 {
  strings:
    $key_75a1 = { 22 d3 [2] 10 f1 [2] 16 c4 [2] 38 c4 [2] 07 d8 }

  condition:
    any of them
}