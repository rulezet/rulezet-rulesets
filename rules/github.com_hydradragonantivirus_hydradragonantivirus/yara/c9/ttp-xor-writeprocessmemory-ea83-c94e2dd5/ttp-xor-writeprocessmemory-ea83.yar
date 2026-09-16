rule TTP_XOR_WriteProcessMemory_ea83 {
  strings:
    $key_ea83 = { bd f1 [2] 8f d3 [2] 89 e6 [2] a7 e6 [2] 98 fa }

  condition:
    any of them
}