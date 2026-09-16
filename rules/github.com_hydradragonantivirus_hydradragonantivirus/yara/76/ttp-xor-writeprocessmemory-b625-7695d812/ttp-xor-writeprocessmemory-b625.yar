rule TTP_XOR_WriteProcessMemory_b625 {
  strings:
    $key_b625 = { e1 57 [2] d3 75 [2] d5 40 [2] fb 40 [2] c4 5c }

  condition:
    any of them
}