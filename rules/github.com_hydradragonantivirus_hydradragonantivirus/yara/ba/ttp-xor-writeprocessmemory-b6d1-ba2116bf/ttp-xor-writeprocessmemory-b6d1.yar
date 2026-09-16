rule TTP_XOR_WriteProcessMemory_b6d1 {
  strings:
    $key_b6d1 = { e1 a3 [2] d3 81 [2] d5 b4 [2] fb b4 [2] c4 a8 }

  condition:
    any of them
}