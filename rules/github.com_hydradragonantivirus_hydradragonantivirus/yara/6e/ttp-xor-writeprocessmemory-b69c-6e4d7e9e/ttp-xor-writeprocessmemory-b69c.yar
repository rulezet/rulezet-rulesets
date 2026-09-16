rule TTP_XOR_WriteProcessMemory_b69c {
  strings:
    $key_b69c = { e1 ee [2] d3 cc [2] d5 f9 [2] fb f9 [2] c4 e5 }

  condition:
    any of them
}