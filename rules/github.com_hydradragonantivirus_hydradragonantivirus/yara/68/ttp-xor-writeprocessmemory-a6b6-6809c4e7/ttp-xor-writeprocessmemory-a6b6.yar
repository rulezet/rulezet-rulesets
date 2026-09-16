rule TTP_XOR_WriteProcessMemory_a6b6 {
  strings:
    $key_a6b6 = { f1 c4 [2] c3 e6 [2] c5 d3 [2] eb d3 [2] d4 cf }

  condition:
    any of them
}