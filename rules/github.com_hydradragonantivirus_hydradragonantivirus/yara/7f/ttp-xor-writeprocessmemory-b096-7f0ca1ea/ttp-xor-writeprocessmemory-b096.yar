rule TTP_XOR_WriteProcessMemory_b096 {
  strings:
    $key_b096 = { e7 e4 [2] d5 c6 [2] d3 f3 [2] fd f3 [2] c2 ef }

  condition:
    any of them
}