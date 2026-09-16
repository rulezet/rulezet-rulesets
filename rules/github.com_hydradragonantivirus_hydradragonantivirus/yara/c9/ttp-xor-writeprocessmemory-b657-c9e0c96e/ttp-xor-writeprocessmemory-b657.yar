rule TTP_XOR_WriteProcessMemory_b657 {
  strings:
    $key_b657 = { e1 25 [2] d3 07 [2] d5 32 [2] fb 32 [2] c4 2e }

  condition:
    any of them
}