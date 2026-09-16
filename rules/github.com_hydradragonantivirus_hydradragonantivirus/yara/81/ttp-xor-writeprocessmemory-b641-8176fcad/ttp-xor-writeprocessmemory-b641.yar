rule TTP_XOR_WriteProcessMemory_b641 {
  strings:
    $key_b641 = { e1 33 [2] d3 11 [2] d5 24 [2] fb 24 [2] c4 38 }

  condition:
    any of them
}