rule TTP_XOR_WriteProcessMemory_7b83 {
  strings:
    $key_7b83 = { 2c f1 [2] 1e d3 [2] 18 e6 [2] 36 e6 [2] 09 fa }

  condition:
    any of them
}