rule TTP_XOR_WriteProcessMemory_b603 {
  strings:
    $key_b603 = { e1 71 [2] d3 53 [2] d5 66 [2] fb 66 [2] c4 7a }

  condition:
    any of them
}