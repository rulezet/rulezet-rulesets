rule TTP_XOR_WriteProcessMemory_b6d2 {
  strings:
    $key_b6d2 = { e1 a0 [2] d3 82 [2] d5 b7 [2] fb b7 [2] c4 ab }

  condition:
    any of them
}