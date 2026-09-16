rule TTP_XOR_WriteProcessMemory_15a1 {
  strings:
    $key_15a1 = { 42 d3 [2] 70 f1 [2] 76 c4 [2] 58 c4 [2] 67 d8 }

  condition:
    any of them
}