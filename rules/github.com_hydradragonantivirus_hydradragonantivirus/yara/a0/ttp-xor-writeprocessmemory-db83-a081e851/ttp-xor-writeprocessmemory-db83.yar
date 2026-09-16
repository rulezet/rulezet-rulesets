rule TTP_XOR_WriteProcessMemory_db83 {
  strings:
    $key_db83 = { 8c f1 [2] be d3 [2] b8 e6 [2] 96 e6 [2] a9 fa }

  condition:
    any of them
}