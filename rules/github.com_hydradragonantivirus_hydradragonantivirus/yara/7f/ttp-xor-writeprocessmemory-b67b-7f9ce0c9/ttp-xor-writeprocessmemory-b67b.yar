rule TTP_XOR_WriteProcessMemory_b67b {
  strings:
    $key_b67b = { e1 09 [2] d3 2b [2] d5 1e [2] fb 1e [2] c4 02 }

  condition:
    any of them
}