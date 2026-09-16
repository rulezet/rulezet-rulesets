rule TTP_XOR_WriteProcessMemory_e0a1 {
  strings:
    $key_e0a1 = { b7 d3 [2] 85 f1 [2] 83 c4 [2] ad c4 [2] 92 d8 }

  condition:
    any of them
}