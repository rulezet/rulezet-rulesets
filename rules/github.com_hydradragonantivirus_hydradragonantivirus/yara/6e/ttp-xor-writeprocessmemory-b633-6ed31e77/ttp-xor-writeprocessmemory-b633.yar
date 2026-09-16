rule TTP_XOR_WriteProcessMemory_b633 {
  strings:
    $key_b633 = { e1 41 [2] d3 63 [2] d5 56 [2] fb 56 [2] c4 4a }

  condition:
    any of them
}