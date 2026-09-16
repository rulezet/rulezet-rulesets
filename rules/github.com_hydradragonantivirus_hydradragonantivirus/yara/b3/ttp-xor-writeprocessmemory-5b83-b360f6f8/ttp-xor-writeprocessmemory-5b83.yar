rule TTP_XOR_WriteProcessMemory_5b83 {
  strings:
    $key_5b83 = { 0c f1 [2] 3e d3 [2] 38 e6 [2] 16 e6 [2] 29 fa }

  condition:
    any of them
}