rule TTP_XOR_WriteProcessMemory_b6a9 {
  strings:
    $key_b6a9 = { e1 db [2] d3 f9 [2] d5 cc [2] fb cc [2] c4 d0 }

  condition:
    any of them
}