rule TTP_XOR_WriteProcessMemory_2983 {
  strings:
    $key_2983 = { 7e f1 [2] 4c d3 [2] 4a e6 [2] 64 e6 [2] 5b fa }

  condition:
    any of them
}