rule TTP_XOR_WriteProcessMemory_b66b {
  strings:
    $key_b66b = { e1 19 [2] d3 3b [2] d5 0e [2] fb 0e [2] c4 12 }

  condition:
    any of them
}