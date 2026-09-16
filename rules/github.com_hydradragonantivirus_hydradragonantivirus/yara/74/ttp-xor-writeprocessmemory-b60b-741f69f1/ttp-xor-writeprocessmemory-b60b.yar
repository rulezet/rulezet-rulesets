rule TTP_XOR_WriteProcessMemory_b60b {
  strings:
    $key_b60b = { e1 79 [2] d3 5b [2] d5 6e [2] fb 6e [2] c4 72 }

  condition:
    any of them
}