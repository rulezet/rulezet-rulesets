rule TTP_XOR_WriteProcessMemory_12a1 {
  strings:
    $key_12a1 = { 45 d3 [2] 77 f1 [2] 71 c4 [2] 5f c4 [2] 60 d8 }

  condition:
    any of them
}