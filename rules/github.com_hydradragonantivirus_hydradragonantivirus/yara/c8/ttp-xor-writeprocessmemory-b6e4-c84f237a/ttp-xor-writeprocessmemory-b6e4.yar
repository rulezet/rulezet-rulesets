rule TTP_XOR_WriteProcessMemory_b6e4 {
  strings:
    $key_b6e4 = { e1 96 [2] d3 b4 [2] d5 81 [2] fb 81 [2] c4 9d }

  condition:
    any of them
}