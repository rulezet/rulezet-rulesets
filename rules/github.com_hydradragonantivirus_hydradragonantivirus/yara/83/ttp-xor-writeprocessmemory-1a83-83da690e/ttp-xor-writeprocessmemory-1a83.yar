rule TTP_XOR_WriteProcessMemory_1a83 {
  strings:
    $key_1a83 = { 4d f1 [2] 7f d3 [2] 79 e6 [2] 57 e6 [2] 68 fa }

  condition:
    any of them
}