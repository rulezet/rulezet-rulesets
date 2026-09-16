rule TTP_XOR_WriteProcessMemory_b6f3 {
  strings:
    $key_b6f3 = { e1 81 [2] d3 a3 [2] d5 96 [2] fb 96 [2] c4 8a }

  condition:
    any of them
}