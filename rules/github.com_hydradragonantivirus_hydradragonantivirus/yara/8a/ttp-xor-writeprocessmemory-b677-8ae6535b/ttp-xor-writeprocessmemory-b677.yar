rule TTP_XOR_WriteProcessMemory_b677 {
  strings:
    $key_b677 = { e1 05 [2] d3 27 [2] d5 12 [2] fb 12 [2] c4 0e }

  condition:
    any of them
}