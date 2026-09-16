rule TTP_XOR_WriteProcessMemory_b684 {
  strings:
    $key_b684 = { e1 f6 [2] d3 d4 [2] d5 e1 [2] fb e1 [2] c4 fd }

  condition:
    any of them
}