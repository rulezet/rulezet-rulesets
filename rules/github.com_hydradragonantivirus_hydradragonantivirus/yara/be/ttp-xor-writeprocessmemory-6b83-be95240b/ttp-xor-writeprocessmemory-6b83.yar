rule TTP_XOR_WriteProcessMemory_6b83 {
  strings:
    $key_6b83 = { 3c f1 [2] 0e d3 [2] 08 e6 [2] 26 e6 [2] 19 fa }

  condition:
    any of them
}