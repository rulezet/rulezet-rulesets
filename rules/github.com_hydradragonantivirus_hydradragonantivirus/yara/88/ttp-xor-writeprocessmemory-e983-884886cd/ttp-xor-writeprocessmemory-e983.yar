rule TTP_XOR_WriteProcessMemory_e983 {
  strings:
    $key_e983 = { be f1 [2] 8c d3 [2] 8a e6 [2] a4 e6 [2] 9b fa }

  condition:
    any of them
}