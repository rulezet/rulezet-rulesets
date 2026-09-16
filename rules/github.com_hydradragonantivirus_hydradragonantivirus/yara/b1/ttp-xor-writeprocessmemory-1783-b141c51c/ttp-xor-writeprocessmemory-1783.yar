rule TTP_XOR_WriteProcessMemory_1783 {
  strings:
    $key_1783 = { 40 f1 [2] 72 d3 [2] 74 e6 [2] 5a e6 [2] 65 fa }

  condition:
    any of them
}