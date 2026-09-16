rule TTP_XOR_WriteProcessMemory_b6f1 {
  strings:
    $key_b6f1 = { e1 83 [2] d3 a1 [2] d5 94 [2] fb 94 [2] c4 88 }

  condition:
    any of them
}