rule TTP_XOR_WriteProcessMemory_b630 {
  strings:
    $key_b630 = { e1 42 [2] d3 60 [2] d5 55 [2] fb 55 [2] c4 49 }

  condition:
    any of them
}