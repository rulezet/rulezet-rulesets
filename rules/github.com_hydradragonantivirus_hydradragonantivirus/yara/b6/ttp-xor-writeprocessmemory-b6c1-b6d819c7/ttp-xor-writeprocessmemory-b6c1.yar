rule TTP_XOR_WriteProcessMemory_b6c1 {
  strings:
    $key_b6c1 = { e1 b3 [2] d3 91 [2] d5 a4 [2] fb a4 [2] c4 b8 }

  condition:
    any of them
}