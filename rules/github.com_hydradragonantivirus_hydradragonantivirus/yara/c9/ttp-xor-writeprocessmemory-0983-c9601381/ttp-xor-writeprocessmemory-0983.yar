rule TTP_XOR_WriteProcessMemory_0983 {
  strings:
    $key_0983 = { 5e f1 [2] 6c d3 [2] 6a e6 [2] 44 e6 [2] 7b fa }

  condition:
    any of them
}