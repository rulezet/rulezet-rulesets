rule TTP_XOR_WriteProcessMemory_27a1 {
  strings:
    $key_27a1 = { 70 d3 [2] 42 f1 [2] 44 c4 [2] 6a c4 [2] 55 d8 }

  condition:
    any of them
}