rule TTP_XOR_WriteProcessMemory_b637 {
  strings:
    $key_b637 = { e1 45 [2] d3 67 [2] d5 52 [2] fb 52 [2] c4 4e }

  condition:
    any of them
}