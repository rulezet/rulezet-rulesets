rule TTP_XOR_WriteProcessMemory_b6ac {
  strings:
    $key_b6ac = { e1 de [2] d3 fc [2] d5 c9 [2] fb c9 [2] c4 d5 }

  condition:
    any of them
}