rule TTP_XOR_WriteProcessMemory_b602 {
  strings:
    $key_b602 = { e1 70 [2] d3 52 [2] d5 67 [2] fb 67 [2] c4 7b }

  condition:
    any of them
}