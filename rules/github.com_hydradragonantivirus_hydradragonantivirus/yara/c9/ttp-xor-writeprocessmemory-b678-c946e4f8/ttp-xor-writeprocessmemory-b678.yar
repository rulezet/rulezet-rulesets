rule TTP_XOR_WriteProcessMemory_b678 {
  strings:
    $key_b678 = { e1 0a [2] d3 28 [2] d5 1d [2] fb 1d [2] c4 01 }

  condition:
    any of them
}