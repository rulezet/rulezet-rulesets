rule TTP_XOR_WriteProcessMemory_1183 {
  strings:
    $key_1183 = { 46 f1 [2] 74 d3 [2] 72 e6 [2] 5c e6 [2] 63 fa }

  condition:
    any of them
}