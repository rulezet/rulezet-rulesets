rule TTP_XOR_WriteProcessMemory_21a1 {
  strings:
    $key_21a1 = { 76 d3 [2] 44 f1 [2] 42 c4 [2] 6c c4 [2] 53 d8 }

  condition:
    any of them
}