rule TTP_XOR_WriteProcessMemory_2a83 {
  strings:
    $key_2a83 = { 7d f1 [2] 4f d3 [2] 49 e6 [2] 67 e6 [2] 58 fa }

  condition:
    any of them
}