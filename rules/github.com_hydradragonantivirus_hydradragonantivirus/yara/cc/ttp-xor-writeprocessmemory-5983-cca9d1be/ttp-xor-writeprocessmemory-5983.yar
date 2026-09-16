rule TTP_XOR_WriteProcessMemory_5983 {
  strings:
    $key_5983 = { 0e f1 [2] 3c d3 [2] 3a e6 [2] 14 e6 [2] 2b fa }

  condition:
    any of them
}