rule TTP_XOR_WriteProcessMemory_1b83 {
  strings:
    $key_1b83 = { 4c f1 [2] 7e d3 [2] 78 e6 [2] 56 e6 [2] 69 fa }

  condition:
    any of them
}