rule TTP_XOR_WriteProcessMemory_8c83 {
  strings:
    $key_8c83 = { db f1 [2] e9 d3 [2] ef e6 [2] c1 e6 [2] fe fa }

  condition:
    any of them
}