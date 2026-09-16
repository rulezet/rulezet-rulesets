rule TTP_XOR_WriteProcessMemory_01a1 {
  strings:
    $key_01a1 = { 56 d3 [2] 64 f1 [2] 62 c4 [2] 4c c4 [2] 73 d8 }

  condition:
    any of them
}