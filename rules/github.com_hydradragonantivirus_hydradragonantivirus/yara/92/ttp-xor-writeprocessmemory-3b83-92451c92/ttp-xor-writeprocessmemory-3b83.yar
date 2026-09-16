rule TTP_XOR_WriteProcessMemory_3b83 {
  strings:
    $key_3b83 = { 6c f1 [2] 5e d3 [2] 58 e6 [2] 76 e6 [2] 49 fa }

  condition:
    any of them
}