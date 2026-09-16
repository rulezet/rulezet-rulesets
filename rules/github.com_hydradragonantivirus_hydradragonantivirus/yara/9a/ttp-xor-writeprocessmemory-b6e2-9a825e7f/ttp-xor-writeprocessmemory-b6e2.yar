rule TTP_XOR_WriteProcessMemory_b6e2 {
  strings:
    $key_b6e2 = { e1 90 [2] d3 b2 [2] d5 87 [2] fb 87 [2] c4 9b }

  condition:
    any of them
}