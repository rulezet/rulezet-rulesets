rule TTP_XOR_WriteProcessMemory_1583 {
  strings:
    $key_1583 = { 42 f1 [2] 70 d3 [2] 76 e6 [2] 58 e6 [2] 67 fa }

  condition:
    any of them
}