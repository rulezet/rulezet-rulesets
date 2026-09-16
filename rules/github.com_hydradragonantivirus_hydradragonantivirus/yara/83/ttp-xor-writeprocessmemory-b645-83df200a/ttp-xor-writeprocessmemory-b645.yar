rule TTP_XOR_WriteProcessMemory_b645 {
  strings:
    $key_b645 = { e1 37 [2] d3 15 [2] d5 20 [2] fb 20 [2] c4 3c }

  condition:
    any of them
}