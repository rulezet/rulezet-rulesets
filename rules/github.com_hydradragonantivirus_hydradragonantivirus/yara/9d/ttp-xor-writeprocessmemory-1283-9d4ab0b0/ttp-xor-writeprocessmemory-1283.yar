rule TTP_XOR_WriteProcessMemory_1283 {
  strings:
    $key_1283 = { 45 f1 [2] 77 d3 [2] 71 e6 [2] 5f e6 [2] 60 fa }

  condition:
    any of them
}