rule TTP_XOR_WriteProcessMemory_b614 {
  strings:
    $key_b614 = { e1 66 [2] d3 44 [2] d5 71 [2] fb 71 [2] c4 6d }

  condition:
    any of them
}