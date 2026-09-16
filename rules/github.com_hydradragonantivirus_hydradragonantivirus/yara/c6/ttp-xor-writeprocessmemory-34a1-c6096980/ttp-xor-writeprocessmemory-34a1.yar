rule TTP_XOR_WriteProcessMemory_34a1 {
  strings:
    $key_34a1 = { 63 d3 [2] 51 f1 [2] 57 c4 [2] 79 c4 [2] 46 d8 }

  condition:
    any of them
}