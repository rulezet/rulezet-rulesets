rule TTP_XOR_WriteProcessMemory_b608 {
  strings:
    $key_b608 = { e1 7a [2] d3 58 [2] d5 6d [2] fb 6d [2] c4 71 }

  condition:
    any of them
}