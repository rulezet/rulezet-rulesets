rule TTP_XOR_WriteProcessMemory_b6f7 {
  strings:
    $key_b6f7 = { e1 85 [2] d3 a7 [2] d5 92 [2] fb 92 [2] c4 8e }

  condition:
    any of them
}