rule TTP_XOR_WriteProcessMemory_73a1 {
  strings:
    $key_73a1 = { 24 d3 [2] 16 f1 [2] 10 c4 [2] 3e c4 [2] 01 d8 }

  condition:
    any of them
}