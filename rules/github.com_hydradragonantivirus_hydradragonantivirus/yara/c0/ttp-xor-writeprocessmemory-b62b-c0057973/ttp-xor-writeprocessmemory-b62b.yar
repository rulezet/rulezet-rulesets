rule TTP_XOR_WriteProcessMemory_b62b {
  strings:
    $key_b62b = { e1 59 [2] d3 7b [2] d5 4e [2] fb 4e [2] c4 52 }

  condition:
    any of them
}