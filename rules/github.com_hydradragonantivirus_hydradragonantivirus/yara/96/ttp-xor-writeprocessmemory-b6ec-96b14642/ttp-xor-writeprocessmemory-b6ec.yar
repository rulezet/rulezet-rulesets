rule TTP_XOR_WriteProcessMemory_b6ec {
  strings:
    $key_b6ec = { e1 9e [2] d3 bc [2] d5 89 [2] fb 89 [2] c4 95 }

  condition:
    any of them
}