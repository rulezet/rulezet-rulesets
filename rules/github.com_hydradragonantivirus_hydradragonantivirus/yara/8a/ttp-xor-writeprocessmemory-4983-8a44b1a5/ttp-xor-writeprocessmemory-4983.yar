rule TTP_XOR_WriteProcessMemory_4983 {
  strings:
    $key_4983 = { 1e f1 [2] 2c d3 [2] 2a e6 [2] 04 e6 [2] 3b fa }

  condition:
    any of them
}