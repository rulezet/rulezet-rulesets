rule TTP_XOR_WriteProcessMemory_17a1 {
  strings:
    $key_17a1 = { 40 d3 [2] 72 f1 [2] 74 c4 [2] 5a c4 [2] 65 d8 }

  condition:
    any of them
}