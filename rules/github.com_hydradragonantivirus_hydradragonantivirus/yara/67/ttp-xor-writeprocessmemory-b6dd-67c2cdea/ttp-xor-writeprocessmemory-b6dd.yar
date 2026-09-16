rule TTP_XOR_WriteProcessMemory_b6dd {
  strings:
    $key_b6dd = { e1 af [2] d3 8d [2] d5 b8 [2] fb b8 [2] c4 a4 }

  condition:
    any of them
}