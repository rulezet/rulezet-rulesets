rule TTP_XOR_WriteProcessMemory_b643 {
  strings:
    $key_b643 = { e1 31 [2] d3 13 [2] d5 26 [2] fb 26 [2] c4 3a }

  condition:
    any of them
}