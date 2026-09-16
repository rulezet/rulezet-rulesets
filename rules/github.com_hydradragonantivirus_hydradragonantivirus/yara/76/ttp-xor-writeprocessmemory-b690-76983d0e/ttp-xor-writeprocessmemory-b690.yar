rule TTP_XOR_WriteProcessMemory_b690 {
  strings:
    $key_b690 = { e1 e2 [2] d3 c0 [2] d5 f5 [2] fb f5 [2] c4 e9 }

  condition:
    any of them
}