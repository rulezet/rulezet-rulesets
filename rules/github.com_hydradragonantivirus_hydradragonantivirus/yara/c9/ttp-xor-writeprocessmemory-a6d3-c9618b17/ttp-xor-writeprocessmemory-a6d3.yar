rule TTP_XOR_WriteProcessMemory_a6d3 {
  strings:
    $key_a6d3 = { f1 a1 [2] c3 83 [2] c5 b6 [2] eb b6 [2] d4 aa }

  condition:
    any of them
}